package archmap

import (
	"fmt"
	"sort"
	"strings"
)

// Violation is one breach of the perimeter rules.
type Violation struct {
	Rule    string
	File    string
	Line    int
	Func    string
	Object  string
	Message string
}

func (v Violation) String() string {
	where := v.File
	if v.Line > 0 {
		where = fmt.Sprintf("%s:%d", v.File, v.Line)
	}
	if v.Func != "" {
		where += " (" + v.Func + ")"
	}
	return fmt.Sprintf("%s: %s: %s", v.Rule, where, v.Message)
}

// CheckOptions configures rules that depend on the codebase.
type CheckOptions struct {
	// InitCallAllowlist names the functions ("importpath.Name") legacy-mode
	// files may call from package-level variable initializers: constructors
	// of values that do nothing else (error values, regular expressions).
	InitCallAllowlist []string
}

// Check applies the perimeter rules to an analysis of the shipped packages:
//
//   - every analyzed file belongs to exactly one module (the rules fail
//     closed);
//   - no analyzed file belongs to an outside module: code linked into a
//     shipped binary runs in the same process as the perimeter and can change
//     what it does, so it is never outside;
//   - perimeter code names legacy-mode code only in type declarations or from
//     a declared dispatch function, and only the legacy objects that entry
//     lists;
//   - perimeter code installs a legacy value into a perimeter slot only from
//     a declared dispatch function listing it;
//   - hand-written legacy-mode files run nothing at program start (no init
//     or main function, no blank imports, package-level initializers call
//     only allowlisted constructors) and declare no method on a perimeter
//     type that an interface could select;
//   - every dispatch entry names a function that exists and objects it uses.
func Check(m *Manifest, a *Analysis, opts CheckOptions) []Violation {
	c := &checker{m: m, mods: map[string]*Module{}, seen: map[string]bool{}}
	used := map[string]bool{} // "file\x00func\x00object" a dispatch entry needs

	for _, r := range a.Refs {
		from, to := c.module(r.From), c.module(r.To)
		if from == nil || to == nil {
			c.unclassified(r.From, from)
			c.unclassified(r.To, to)
			continue
		}
		if from.Tier != TierCore || to.Tier != TierLegacy || r.InTypeDecl {
			continue
		}
		if m.MayDispatch(r.From, r.Func, r.Object) {
			used[r.From+"\x00"+r.Func+"\x00"+r.Object] = true
			continue
		}
		c.add(Violation{File: r.From, Line: r.Line, Func: r.Func, Object: r.Object}, "core-calls-legacy",
			"perimeter module %q names legacy-mode %s (%s) outside a dispatch entry that lists it", from.Name, r.Object, to.Name)
	}

	for _, f := range a.Flows {
		at, origin, slot := c.module(f.File), c.module(f.Origin), c.module(f.Slot)
		if at == nil || origin == nil || slot == nil {
			c.unclassified(f.File, at)
			c.unclassified(f.Origin, origin)
			c.unclassified(f.Slot, slot)
			continue
		}
		// A hand-over written in legacy code happens only while legacy code
		// runs, which the dispatch rules already confine.
		if at.Tier != TierCore || origin.Tier != TierLegacy || slot.Tier != TierCore {
			continue
		}
		if m.MayDispatch(f.File, f.Func, f.OriginObject) {
			used[f.File+"\x00"+f.Func+"\x00"+f.OriginObject] = true
			continue
		}
		c.add(Violation{File: f.File, Line: f.Line, Func: f.Func, Object: f.OriginObject + " => " + f.SlotObject}, "legacy-flows-into-core",
			"legacy-mode %s is installed into %s of perimeter module %q outside a dispatch entry that lists it", f.OriginObject, f.SlotObject, slot.Name)
	}

	for _, md := range a.Methods {
		mod, recv := c.module(md.File), c.module(md.RecvFile)
		if mod == nil || recv == nil {
			c.unclassified(md.File, mod)
			c.unclassified(md.RecvFile, recv)
			continue
		}
		// A legacy method only a direct call can reach is confined by the
		// dispatch rules. One that an interface could select would change
		// what perimeter code does with that type in every mode.
		method := md.Name[strings.LastIndexByte(md.Name, '.')+1:]
		if mod.Tier == TierLegacy && !mod.Generated && recv.Tier == TierCore && a.InterfaceMethods[method] {
			c.add(Violation{File: md.File, Line: md.Line, Object: md.Name}, "legacy-method-on-core-type",
				"legacy-mode file declares method %s on a perimeter type, and an interface has a method of that name; perimeter code could run it in every mode", md.Name)
		}
	}

	allowed := map[string]bool{}
	for _, fn := range opts.InitCallAllowlist {
		allowed[fn] = true
	}
	files := make([]string, 0, len(a.Files))
	for f := range a.Files {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, file := range files {
		facts := a.Files[file]
		mod := c.module(file)
		switch {
		case mod == nil:
			c.unclassified(file, nil)
		case mod.Tier == TierOutside:
			c.add(Violation{File: file, Object: mod.Name}, "shipped-outside",
				"module %q is outside the perimeter but this file is linked into a shipped binary", mod.Name)
		case mod.Tier == TierLegacy && !mod.Generated:
			// Generated protocol code registers its types at start-up; that
			// is accepted (and documented) rather than checked.
			if facts.Init {
				c.add(Violation{File: file, Object: "init"}, "legacy-runs-at-init",
					"legacy-mode file has an init function, which runs in every mode")
			}
			if facts.Main {
				c.add(Violation{File: file, Object: "main"}, "legacy-runs-at-init",
					"legacy-mode file declares the program's main function")
			}
			for _, imp := range facts.BlankImports {
				c.add(Violation{File: file, Object: "import _ " + imp}, "legacy-runs-at-init",
					"legacy-mode file imports %s only for its initialization, which runs in every mode", imp)
			}
			for _, call := range facts.InitCalls {
				if !allowed[call.Callee] {
					c.add(Violation{File: file, Line: call.Line, Object: call.Callee}, "legacy-runs-at-init",
						"legacy-mode package-level initializer calls %s, which runs in every mode", call.Callee)
				}
			}
		}
	}

	for _, d := range m.Dispatch {
		facts := a.Files[d.File]
		if facts == nil || !contains(facts.Decls, d.Function) {
			c.add(Violation{File: d.File, Object: d.Function}, "stale-dispatch",
				"dispatch entry names %s, which %s does not declare", d.Function, d.File)
			continue
		}
		for _, o := range d.Objects {
			if !used[d.File+"\x00"+d.Function+"\x00"+o] {
				c.add(Violation{File: d.File, Func: d.Function, Object: o}, "stale-dispatch",
					"dispatch entry for %s lists %s, which it no longer names", d.Function, o)
			}
		}
	}
	return c.out
}

type checker struct {
	m    *Manifest
	mods map[string]*Module
	seen map[string]bool
	out  []Violation
}

func (c *checker) module(file string) *Module {
	if mod, ok := c.mods[file]; ok {
		return mod
	}
	mods, err := c.m.Classify(file)
	var mod *Module
	if err == nil && len(mods) == 1 {
		mod = mods[0]
	}
	c.mods[file] = mod
	return mod
}

func (c *checker) unclassified(file string, mod *Module) {
	if mod != nil {
		return
	}
	c.add(Violation{File: file, Object: file}, "unclassified", "no single module claims this file")
}

func (c *checker) add(v Violation, rule, format string, args ...any) {
	v.Rule = rule
	v.Message = fmt.Sprintf(format, args...)
	key := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s", v.Rule, v.File, v.Line, v.Func, v.Object)
	if v.Rule == "unclassified" {
		key = v.Rule + "\x00" + v.File
	}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.out = append(c.out, v)
}

func contains(sorted []string, s string) bool {
	i := sort.SearchStrings(sorted, s)
	return i < len(sorted) && sorted[i] == s
}
