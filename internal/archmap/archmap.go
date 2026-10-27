// Package archmap reads the module map of the repository (which source files
// belong to which module, and whether that module is inside the security
// perimeter) and counts non-comment source lines per file.
//
// The map lives in docs/architecture/modules.toml. internal/archtest enforces
// it in CI and cmd/perimeter-report turns it into the per-module size report
// used to scope external audits (RD-1367).
package archmap

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// Tier says whether a module is part of the audited security perimeter.
type Tier string

const (
	// TierCore modules are the perimeter of a Reth-mode (V2) deployment: a
	// bug in them can leak data or grant access.
	TierCore Tier = "core"
	// TierLegacy modules are security-critical only in the legacy or V1
	// signed-approval modes, which a Reth-mode deployment never selects. They
	// ship in the same binary, so the rules confine when they can run.
	TierLegacy Tier = "legacy"
	// TierOutside modules never ship in a release binary: clients, tooling,
	// demos. They reach the system only through its network API.
	TierOutside Tier = "outside"
)

// Module is one entry of the module map.
type Module struct {
	Name    string   `toml:"name"`
	Tier    Tier     `toml:"tier"`
	Summary string   `toml:"summary"`
	Owner   string   `toml:"owner"`
	Paths   []string `toml:"paths"`
	// Except carves files out of Paths for another module to claim.
	Except []string `toml:"except"`
	// AuditScope groups core modules into separately quotable audit scopes.
	AuditScope string `toml:"audit_scope"`
	// Data marks modules that read or write stored or chain data directly.
	// It is recorded, not enforced: no rule checks yet that other modules
	// reach that data only through these.
	Data bool `toml:"data"`
	// Generated marks machine-generated code (protocol buffers, API
	// documents). It is classified so the rules can follow references into
	// it, but its size is reported separately from the audited totals.
	Generated bool `toml:"generated"`
	// Generator, required for generated modules, must appear in each file's
	// generated-code header, so a hand-written file cannot claim the flag.
	Generator string `toml:"generator"`
}

// Dispatch is a perimeter function allowed to reach legacy-mode code, and
// exactly which legacy objects it may name, with the condition that keeps the
// legacy path out of a Reth-mode deployment.
type Dispatch struct {
	File     string   `toml:"file"`
	Function string   `toml:"function"` // "Type.Method" or "Name"
	Objects  []string `toml:"objects"`  // legacy objects it may name, as Ref.Object
	Reason   string   `toml:"reason"`
}

// Scope selects the source files the map must cover.
type Scope struct {
	Include []string `toml:"include"`
	Exclude []string `toml:"exclude"`
}

// AuditInputs are non-source files that change what ships or how the rules
// judge it: dependency locks, build files, the rules engine itself.
type AuditInputs struct {
	Paths []string `toml:"paths"`
}

// Manifest is the parsed module map.
type Manifest struct {
	Scope       Scope       `toml:"scope"`
	AuditInputs AuditInputs `toml:"audit_inputs"`
	Modules     []*Module   `toml:"module"`
	Dispatch    []Dispatch  `toml:"dispatch"`

	byName   map[string]*Module
	dispatch map[string]map[string]bool
}

// Load reads and validates a manifest file.
func Load(path string) (*Manifest, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse validates a manifest.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	meta, err := toml.Decode(string(data), &m)
	if err != nil {
		return nil, fmt.Errorf("parse module map: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("module map has unknown keys: %v", undecoded)
	}
	m.byName = make(map[string]*Module, len(m.Modules))
	for _, mod := range m.Modules {
		if mod.Name == "" {
			return nil, fmt.Errorf("module without a name")
		}
		if _, dup := m.byName[mod.Name]; dup {
			return nil, fmt.Errorf("duplicate module %q", mod.Name)
		}
		m.byName[mod.Name] = mod
		switch mod.Tier {
		case TierCore, TierLegacy, TierOutside:
		default:
			return nil, fmt.Errorf("module %q: unknown tier %q", mod.Name, mod.Tier)
		}
		if strings.TrimSpace(mod.Summary) == "" {
			return nil, fmt.Errorf("module %q needs a summary", mod.Name)
		}
		if strings.TrimSpace(mod.Owner) == "" {
			return nil, fmt.Errorf("module %q needs an owner", mod.Name)
		}
		if len(mod.Paths) == 0 {
			return nil, fmt.Errorf("module %q has no paths", mod.Name)
		}
		for _, p := range append(append([]string(nil), mod.Paths...), mod.Except...) {
			if _, err := compile(p); err != nil {
				return nil, fmt.Errorf("module %q: %w", mod.Name, err)
			}
		}
		if mod.Generated && strings.TrimSpace(mod.Generator) == "" {
			return nil, fmt.Errorf("module %q: generated modules name their generator", mod.Name)
		}
		if !mod.Generated && mod.Generator != "" {
			return nil, fmt.Errorf("module %q: generator applies to generated modules only", mod.Name)
		}
		if (mod.Tier == TierCore) != (mod.AuditScope != "") {
			if mod.Tier == TierCore {
				return nil, fmt.Errorf("module %q: core modules need an audit_scope", mod.Name)
			}
			return nil, fmt.Errorf("module %q: audit_scope applies to core modules only", mod.Name)
		}
	}
	m.dispatch = make(map[string]map[string]bool, len(m.Dispatch))
	for _, d := range m.Dispatch {
		if d.File == "" || d.Function == "" {
			return nil, fmt.Errorf("dispatch entry needs a file and a function")
		}
		key := d.File + "\x00" + d.Function
		if m.dispatch[key] != nil {
			return nil, fmt.Errorf("dispatch %s %s is declared twice", d.File, d.Function)
		}
		if strings.TrimSpace(d.Reason) == "" {
			return nil, fmt.Errorf("dispatch %s %s needs a reason", d.File, d.Function)
		}
		if len(d.Objects) == 0 {
			return nil, fmt.Errorf("dispatch %s %s needs the legacy objects it may name", d.File, d.Function)
		}
		m.dispatch[key] = make(map[string]bool, len(d.Objects))
		for _, o := range d.Objects {
			m.dispatch[key][o] = true
		}
	}
	for _, p := range append(append(append([]string(nil), m.Scope.Include...), m.Scope.Exclude...), m.AuditInputs.Paths...) {
		if _, err := compile(p); err != nil {
			return nil, fmt.Errorf("scope: %w", err)
		}
	}
	return &m, nil
}

// Module returns the module with the given name, or nil.
func (m *Manifest) Module(name string) *Module { return m.byName[name] }

// MayDispatch reports whether the function is a declared dispatch point that
// may name the legacy object.
func (m *Manifest) MayDispatch(file, function, object string) bool {
	return m.dispatch[file+"\x00"+function][object]
}

// Classify returns every module whose paths match rel (slash-separated,
// relative to the repository root). A well-formed map yields exactly one.
func (m *Manifest) Classify(rel string) ([]*Module, error) {
	var out []*Module
	for _, mod := range m.Modules {
		in, err := matchAny(mod.Paths, rel)
		if err != nil {
			return nil, err
		}
		if !in {
			continue
		}
		carved, err := matchAny(mod.Except, rel)
		if err != nil {
			return nil, err
		}
		if !carved {
			out = append(out, mod)
		}
	}
	return out, nil
}

// Changes sorts changed paths (relative to the root) into in-scope source
// files and audit inputs, and reports whether the module map itself changed.
// A path can be both a source file and an audit input (the rules engine is
// both) and is then listed in both.
func (m *Manifest) Changes(paths []string, manifestPath string) (files, inputs []string, mapChanged bool, err error) {
	for _, p := range paths {
		if p == manifestPath {
			mapChanged = true
			continue
		}
		input, err := m.IsAuditInput(p)
		if err != nil {
			return nil, nil, false, err
		}
		if input {
			inputs = append(inputs, p)
		}
		in, err := m.InScope(p)
		if err != nil {
			return nil, nil, false, err
		}
		if in {
			files = append(files, p)
		}
	}
	return files, inputs, mapChanged, nil
}

// IsAuditInput reports whether a path is one of the audit inputs.
func (m *Manifest) IsAuditInput(rel string) (bool, error) {
	return matchAny(m.AuditInputs.Paths, rel)
}

// InScope reports whether a path (existing or not) is selected by the scope.
func (m *Manifest) InScope(rel string) (bool, error) {
	in, err := matchAny(m.Scope.Include, rel)
	if err != nil || !in {
		return false, err
	}
	excluded, err := matchAny(m.Scope.Exclude, rel)
	return !excluded, err
}

// Sources lists the files under root that the scope selects, sorted and
// slash-separated relative to root.
func (m *Manifest) Sources(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDir(path, rel, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		in, err := m.InScope(rel)
		if err != nil || !in {
			return err
		}
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out, err
}

// skipDir reports build output, dependency and scratch directories. Each is
// recognized by what it is, not only by its name, so a source directory that
// happens to share a name is still measured.
func skipDir(path, rel, name string) bool {
	switch name {
	case "node_modules", ".next":
		return true
	case ".git", ".tmp":
		return rel == name
	case "target":
		_, err := os.Stat(filepath.Join(filepath.Dir(path), "Cargo.toml"))
		return err == nil
	}
	return false
}

func matchAny(patterns []string, rel string) (bool, error) {
	for _, p := range patterns {
		ok, err := Match(p, rel)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// Match reports whether a slash-separated path matches a glob. `*` matches
// within one path segment, `**` matches any number of segments, and `{a,b}`
// matches either alternative.
func Match(pattern, path string) (bool, error) {
	re, err := compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(path), nil
}

func compile(pattern string) (*regexp.Regexp, error) {
	globMu.Lock()
	defer globMu.Unlock()
	if re, ok := globCache[pattern]; ok {
		return re, nil
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '{':
			end := strings.IndexByte(pattern[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("glob %q: unclosed {", pattern)
			}
			alts := strings.Split(pattern[i+1:i+end], ",")
			for j := range alts {
				alts[j] = regexp.QuoteMeta(alts[j])
			}
			b.WriteString("(?:" + strings.Join(alts, "|") + ")")
			i += end
		case '[', ']':
			return nil, fmt.Errorf("glob %q: character classes are not supported", pattern)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("glob %q: %w", pattern, err)
	}
	globCache[pattern] = re
	return re, nil
}
