package archmap

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Ref is one use, in one source file, of an object declared in another
// source file under the analyzed root.
type Ref struct {
	From string // file containing the use, relative to the root
	Line int    // line of the use
	// Func is the function enclosing the use ("Type.Method" or "Name"), "init"
	// for init functions, or "" at package level.
	Func string
	To   string // file declaring the object
	// Object names what is referenced: "Name" for package-level objects,
	// "Type.Method" for methods and "Type.Field" for struct fields.
	Object string
	// InTypeDecl is set when the use is part of a type declaration (a field
	// or parameter type), which runs nothing.
	InTypeDecl bool
}

// Flow is a value whose type (or function) is declared in one place being
// handed to a slot declared in another: a call argument, a struct field, a
// package-level variable, a slice it is appended to or a channel it is sent
// on. Flows reveal dependency injection, which plain references miss: an
// outside package that receives a data handle through an interface never
// names the data package.
type Flow struct {
	File string // file where the hand-over happens
	Line int
	Func string
	// Origin is the file declaring the value's named type, or the function
	// when a function or method value is passed.
	Origin       string
	OriginObject string
	// Slot is the file declaring the receiving function, field or variable.
	Slot       string
	SlotObject string
}

// InitCall is a function called while a package-level variable is
// initialized, which runs at program start in every mode.
type InitCall struct {
	Line   int
	Callee string // "importpath.Name" or "importpath.Type.Method"
}

// FileFacts are per-file properties the boundary rules look at.
type FileFacts struct {
	Init bool
	Main bool // declares func main
	// BlankImports are packages imported only for their initialization.
	BlankImports []string
	InitCalls    []InitCall
	// Decls are the package-level names the file declares, with methods as
	// "Type.Method".
	Decls []string
}

// Analysis is everything the boundary rules need from the type-checked code.
type Analysis struct {
	Refs    []Ref
	Flows   []Flow
	Methods []MethodDecl
	Files   map[string]*FileFacts
	// InterfaceMethods are the method names of every interface type in the
	// loaded program, named or literal, including dependencies.
	InterfaceMethods map[string]bool
}

// MethodDecl is a method declared in one file on a type declared in another.
type MethodDecl struct {
	File     string
	Line     int
	Name     string // "Type.Method"
	RecvFile string
}

// AnalyzeOptions selects what to load.
type AnalyzeOptions struct {
	Patterns []string
	// BuildFlags are passed to the go command, e.g. a -tags list.
	BuildFlags []string
}

// Analyze type-checks the packages matching opts.Patterns under root (a Go
// module directory) and collects references, flows and file facts between
// non-test source files under root.
func Analyze(root string, opts AnalyzeOptions) (*Analysis, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:        absRoot,
		BuildFlags: opts.BuildFlags,
	}
	pkgs, err := packages.Load(cfg, opts.Patterns...)
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	})
	if len(loadErrs) > 0 {
		return nil, fmt.Errorf("load packages: %s", strings.Join(loadErrs, "; "))
	}

	a := &analyzer{
		root:     absRoot,
		owners:   fieldOwners(pkgs),
		analysis: &Analysis{Files: map[string]*FileFacts{}},
	}
	for _, p := range pkgs {
		a.pkg = p
		for _, f := range p.Syntax {
			a.file(f)
		}
	}
	a.analysis.InterfaceMethods = interfaceMethods(pkgs)
	sortRefs(a.analysis.Refs)
	sortFlows(a.analysis.Flows)
	return a.analysis, nil
}

type analyzer struct {
	root     string
	pkg      *packages.Package
	owners   map[*types.Var]string
	analysis *Analysis
}

// rel maps an absolute file name to a root-relative slash path; ok is false
// for files outside the root (standard library, other modules).
func (a *analyzer) rel(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	r, err := filepath.Rel(a.root, name)
	if err != nil || r == ".." || strings.HasPrefix(r, "../") {
		return "", false
	}
	return filepath.ToSlash(r), true
}

func (a *analyzer) declFile(obj types.Object) (string, bool) {
	if obj == nil || obj.Pkg() == nil || !obj.Pos().IsValid() {
		return "", false
	}
	return a.rel(a.pkg.Fset.PositionFor(obj.Pos(), false).Filename)
}

func (a *analyzer) file(f *ast.File) {
	info := a.pkg.TypesInfo
	fset := a.pkg.Fset
	from, ok := a.rel(fset.PositionFor(f.Pos(), false).Filename)
	if !ok {
		return
	}
	facts := &FileFacts{}
	a.analysis.Files[from] = facts
	for _, imp := range f.Imports {
		if imp.Name != nil && imp.Name.Name == "_" {
			facts.BlankImports = append(facts.BlankImports, strings.Trim(imp.Path.Value, `"`))
		}
	}
	funcs := funcSpans(f, info)
	typeDecls, embedded := typeSpans(f)
	enclosing := func(pos token.Pos) string {
		return innermost(funcs, pos).name
	}
	enclosingFunc := func(pos token.Pos) *types.Func {
		return innermost(funcs, pos).fn
	}
	inTypeDecl := func(pos token.Pos) bool {
		if innermost(embedded, pos).end != 0 {
			return false
		}
		_, ok := spanAt(typeDecls, pos)
		return ok
	}
	a.declarations(f, from, facts)

	addRef := func(ident *ast.Ident, obj types.Object) {
		to, ok := a.declFile(obj)
		if !ok || to == from {
			return
		}
		a.analysis.Refs = append(a.analysis.Refs, Ref{
			From: from, Line: fset.PositionFor(ident.Pos(), false).Line, Func: enclosing(ident.Pos()),
			To: to, Object: objectName(obj, a.owners), InTypeDecl: inTypeDecl(ident.Pos()),
		})
	}
	addFlow := func(at ast.Node, o origin, slot types.Object) {
		slotFile, ok := a.declFile(slot)
		if !ok || !o.ok || o.file == slotFile {
			return
		}
		a.analysis.Flows = append(a.analysis.Flows, Flow{
			File: from, Line: fset.PositionFor(at.Pos(), false).Line, Func: enclosing(at.Pos()),
			Origin: o.file, OriginObject: o.name,
			Slot: slotFile, SlotObject: objectName(slot, a.owners),
		})
	}
	exprFlow := func(at ast.Node, value ast.Expr, slot types.Object) {
		addFlow(at, a.originOfExpr(value, from), slot)
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			addRef(n, info.Uses[n])
		case *ast.SelectorExpr:
			// Promoted fields and methods resolve through Selections.
			if sel := info.Selections[n]; sel != nil && info.Uses[n.Sel] != sel.Obj() {
				addRef(n.Sel, sel.Obj())
			}
		case *ast.CallExpr:
			if tv, ok := info.Types[n.Fun]; ok && tv.IsType() {
				return true // conversion
			}
			if b, ok := builtinCallee(info, n.Fun); ok {
				if b == "append" && len(n.Args) > 1 {
					if slot := slotVar(info, n.Args[0]); slot != nil {
						for _, arg := range n.Args[1:] {
							exprFlow(arg, arg, slot)
						}
					}
				}
				return true
			}
			callee := calleeObject(info, n.Fun)
			if callee == nil {
				return true
			}
			for _, arg := range n.Args {
				exprFlow(arg, arg, callee)
			}
		case *ast.CompositeLit:
			st, ok := underlyingStruct(info.TypeOf(n))
			if !ok {
				// Slice, array and map elements end up wherever the literal
				// goes; attribute them to the enclosing function.
				if fn := enclosingFunc(n.Pos()); fn != nil {
					for _, elt := range n.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							exprFlow(kv, kv.Key, fn)
							exprFlow(kv, kv.Value, fn)
							continue
						}
						exprFlow(elt, elt, fn)
					}
				}
				return true
			}
			for i, elt := range n.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						if field, ok := info.Uses[key].(*types.Var); ok {
							exprFlow(kv, kv.Value, field)
						}
					}
					continue
				}
				if i < st.NumFields() {
					exprFlow(elt, elt, st.Field(i))
				}
			}
		case *ast.AssignStmt:
			switch {
			case len(n.Lhs) == len(n.Rhs):
				for i, lhs := range n.Lhs {
					if slot := slotVar(info, lhs); slot != nil {
						exprFlow(n, n.Rhs[i], slot)
					}
				}
			case len(n.Rhs) == 1:
				tuple, ok := info.TypeOf(n.Rhs[0]).(*types.Tuple)
				if !ok {
					return true
				}
				for i, lhs := range n.Lhs {
					if slot := slotVar(info, lhs); slot != nil && i < tuple.Len() {
						addFlow(n, a.originOfType(tuple.At(i).Type()), slot)
					}
				}
			}
		case *ast.SendStmt:
			if slot := slotVar(info, n.Chan); slot != nil {
				exprFlow(n, n.Value, slot)
			}
		case *ast.ReturnStmt:
			// A returned value is handed to the enclosing function's caller;
			// returns inside function literals have no named slot.
			if fn := enclosingFunc(n.Pos()); fn != nil {
				for _, r := range n.Results {
					exprFlow(r, r, fn)
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) != len(n.Values) {
				return true
			}
			for i, name := range n.Names {
				if obj, ok := info.Defs[name].(*types.Var); ok {
					exprFlow(n, n.Values[i], obj)
				}
			}
		}
		return true
	})
}

// declarations records the package-level names a file declares, whether it
// has an init function and what its variable initializers call.
func (a *analyzer) declarations(f *ast.File, from string, facts *FileFacts) {
	info := a.pkg.TypesInfo
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				switch d.Name.Name {
				case "init":
					facts.Init = true
					continue
				case "main":
					facts.Main = a.pkg.Name == "main"
				}
				facts.Decls = append(facts.Decls, d.Name.Name)
				continue
			}
			fn, ok := info.Defs[d.Name].(*types.Func)
			if !ok {
				continue
			}
			tn := namedTypeName(fn.Type().(*types.Signature).Recv().Type())
			if tn == nil {
				continue
			}
			name := tn.Name() + "." + d.Name.Name
			facts.Decls = append(facts.Decls, name)
			if recvFile, ok := a.declFile(tn); ok && recvFile != from {
				a.analysis.Methods = append(a.analysis.Methods, MethodDecl{
					File: from, Line: a.pkg.Fset.PositionFor(d.Pos(), false).Line, Name: name, RecvFile: recvFile,
				})
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					facts.Decls = append(facts.Decls, s.Name.Name)
					if st, ok := s.Type.(*ast.StructType); ok {
						for _, field := range st.Fields.List {
							for _, n := range field.Names {
								facts.Decls = append(facts.Decls, s.Name.Name+"."+n.Name)
							}
						}
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						facts.Decls = append(facts.Decls, n.Name)
					}
					if d.Tok == token.VAR {
						for _, v := range s.Values {
							facts.InitCalls = append(facts.InitCalls, a.initCalls(v)...)
						}
					}
				}
			}
		}
	}
	sort.Strings(facts.Decls)
}

// origin names where a value comes from.
type origin struct {
	file string // declaring file under the root
	name string
	ok   bool
}

// originOfExpr is the declaring file of a passed function or method value,
// the current file for a function literal, or the origin of the value's type.
func (a *analyzer) originOfExpr(e ast.Expr, current string) origin {
	info := a.pkg.TypesInfo
	e = ast.Unparen(e)
	if _, ok := e.(*ast.FuncLit); ok {
		return origin{file: current, name: "func literal", ok: true}
	}
	var obj types.Object
	switch x := e.(type) {
	case *ast.Ident:
		obj = info.Uses[x]
	case *ast.SelectorExpr:
		if sel := info.Selections[x]; sel != nil && sel.Kind() == types.MethodVal {
			obj = sel.Obj()
		} else if sel == nil {
			obj = info.Uses[x.Sel]
		}
	}
	if fn, ok := obj.(*types.Func); ok {
		if f, ok := a.declFile(fn); ok {
			return origin{file: f, name: objectName(fn, a.owners), ok: true}
		}
		return origin{}
	}
	return a.originOfType(info.TypeOf(e))
}

// originOfType is the declaring file of the named type a value carries,
// looking through pointers, slices, arrays, maps and channels.
func (a *analyzer) originOfType(t types.Type) origin {
	tn := namedTypeName(t)
	if tn == nil || tn.Pkg() == nil || !tn.Pos().IsValid() {
		return origin{}
	}
	if f, ok := a.declFile(tn); ok {
		return origin{file: f, name: tn.Name(), ok: true}
	}
	return origin{}
}

// initCalls lists every call an initializer expression makes when it is
// evaluated: named functions as "importpath.Name", a called function literal
// as "func literal", anything else as "function value <expr>". The bodies of
// function literals that are not called here do not run. Builtins and
// conversions are not calls.
func (a *analyzer) initCalls(e ast.Expr) []InitCall {
	info := a.pkg.TypesInfo
	var out []InitCall
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			if tv, ok := info.Types[n.Fun]; ok && tv.IsType() {
				return true
			}
			if _, ok := builtinCallee(info, n.Fun); ok {
				return true
			}
			line := a.pkg.Fset.PositionFor(n.Pos(), false).Line
			switch fun := ast.Unparen(n.Fun).(type) {
			case *ast.FuncLit:
				out = append(out, InitCall{Line: line, Callee: "func literal"})
				for _, arg := range n.Args {
					out = append(out, a.initCalls(arg)...)
				}
				return false
			default:
				if fn, ok := calleeObject(info, fun).(*types.Func); ok && fn.Pkg() != nil {
					out = append(out, InitCall{Line: line, Callee: fn.Pkg().Path() + "." + objectName(fn, a.owners)})
				} else {
					out = append(out, InitCall{Line: line, Callee: "function value " + types.ExprString(fun)})
				}
			}
		}
		return true
	})
	return out
}

type span struct {
	pos, end token.Pos
	name     string
	fn       *types.Func // the declared function, nil for literals and types
}

// innermost returns the smallest span containing pos.
func innermost(spans []span, pos token.Pos) span {
	var best span
	for _, s := range spans {
		if s.pos <= pos && pos <= s.end && (best.end == 0 || s.end-s.pos < best.end-best.pos) {
			best = s
		}
	}
	return best
}

func spanAt(spans []span, pos token.Pos) (span, bool) {
	i := sort.Search(len(spans), func(i int) bool { return spans[i].end >= pos })
	if i < len(spans) && spans[i].pos <= pos {
		return spans[i], true
	}
	return span{}, false
}

// funcSpans returns the function declarations of a file and the function
// literals inside them. A literal is named after its enclosing function plus
// ".func": it can run later, outside the function that created it, so it
// does not share that function's boundary permissions.
func funcSpans(f *ast.File, info *types.Info) []span {
	var out []span
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			name = receiverTypeName(fd.Recv.List[0].Type) + "." + name
		}
		fn, _ := info.Defs[fd.Name].(*types.Func)
		out = append(out, span{pos: fd.Pos(), end: fd.End(), name: name, fn: fn})
		if fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				out = append(out, span{pos: lit.Pos(), end: lit.End(), name: name + ".func"})
			}
			return true
		})
	}
	return out
}

// typeSpans returns the type declarations of a file, and separately the
// embedded fields in them: embedding gives the declared type the embedded
// type's methods, so it is not a mere declaration.
func typeSpans(f *ast.File) (decls, embedded []span) {
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			decls = append(decls, span{pos: spec.Pos(), end: spec.End()})
			ast.Inspect(spec, func(n ast.Node) bool {
				if st, ok := n.(*ast.StructType); ok {
					for _, field := range st.Fields.List {
						if len(field.Names) == 0 {
							embedded = append(embedded, span{pos: field.Type.Pos(), end: field.Type.End()})
						}
					}
				}
				return true
			})
		}
	}
	sort.Slice(decls, func(i, j int) bool { return decls[i].pos < decls[j].pos })
	return decls, embedded
}

func receiverTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	case *ast.IndexListExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// writtenIdent returns the identifier an assignment target names, looking
// through selection, indexing and dereference.
func writtenIdent(e ast.Expr) *ast.Ident {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		return x
	case *ast.SelectorExpr:
		return x.Sel
	case *ast.IndexExpr:
		return writtenIdent(x.X)
	case *ast.StarExpr:
		return writtenIdent(x.X)
	}
	return nil
}

func builtinCallee(info *types.Info, fun ast.Expr) (string, bool) {
	id, ok := ast.Unparen(fun).(*ast.Ident)
	if !ok {
		return "", false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	if !ok {
		return "", false
	}
	return b.Name(), true
}

func calleeObject(info *types.Info, fun ast.Expr) types.Object {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		if fn, ok := info.Uses[f].(*types.Func); ok {
			return fn
		}
	case *ast.SelectorExpr:
		if sel := info.Selections[f]; sel != nil {
			if fn, ok := sel.Obj().(*types.Func); ok {
				return fn
			}
			return nil
		}
		if fn, ok := info.Uses[f.Sel].(*types.Func); ok {
			return fn
		}
	case *ast.IndexExpr:
		return calleeObject(info, f.X)
	case *ast.IndexListExpr:
		return calleeObject(info, f.X)
	}
	return nil
}

// slotVar returns the variable or struct field an expression names, looking
// through indexing and dereference.
func slotVar(info *types.Info, e ast.Expr) *types.Var {
	id := writtenIdent(e)
	if id == nil || id.Name == "_" {
		return nil
	}
	obj := info.Uses[id]
	if obj == nil {
		obj = info.Defs[id]
	}
	v, _ := obj.(*types.Var)
	return v
}

func isPackageLevel(v *types.Var) bool {
	return v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
}

func underlyingStruct(t types.Type) (*types.Struct, bool) {
	if t == nil {
		return nil, false
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}

// namedTypeName returns the named type a value of type t carries, looking
// through pointers and containers.
func namedTypeName(t types.Type) *types.TypeName {
	for i := 0; t != nil && i < 8; i++ {
		t = types.Unalias(t)
		switch x := t.(type) {
		case *types.Named:
			return x.Obj()
		case *types.Pointer:
			t = x.Elem()
		case *types.Slice:
			t = x.Elem()
		case *types.Array:
			t = x.Elem()
		case *types.Chan:
			t = x.Elem()
		case *types.Map:
			t = x.Elem()
		default:
			return nil
		}
	}
	return nil
}

func objectName(obj types.Object, owners map[*types.Var]string) string {
	switch o := obj.(type) {
	case *types.Func:
		if sig, ok := o.Type().(*types.Signature); ok && sig.Recv() != nil {
			if tn := namedTypeName(sig.Recv().Type()); tn != nil {
				return tn.Name() + "." + o.Name()
			}
			return "interface." + o.Name()
		}
	case *types.Var:
		if o.IsField() {
			if owner := owners[o]; owner != "" {
				return owner + "." + o.Name()
			}
			return "." + o.Name()
		}
	}
	return obj.Name()
}

// fieldOwners maps every named struct type's fields to the type name, so a
// field use can be reported as Type.Field.
func fieldOwners(pkgs []*packages.Package) map[*types.Var]string {
	owners := map[*types.Var]string{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types == nil {
			return
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			st, ok := tn.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}
			for i := 0; i < st.NumFields(); i++ {
				owners[st.Field(i)] = name
			}
		}
	})
	return owners
}

// interfaceMethods collects the method names of the named interfaces of every
// loaded package and of the interface literals in the analyzed packages.
func interfaceMethods(pkgs []*packages.Package) map[string]bool {
	out := map[string]bool{}
	add := func(t types.Type) {
		if it, ok := t.Underlying().(*types.Interface); ok {
			for i := 0; i < it.NumMethods(); i++ {
				out[it.Method(i).Name()] = true
			}
		}
	}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types == nil {
			return
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if tn, ok := scope.Lookup(name).(*types.TypeName); ok {
				add(tn.Type())
			}
		}
		if p.TypesInfo != nil {
			for _, tv := range p.TypesInfo.Types {
				if tv.Type != nil {
					add(tv.Type)
				}
			}
		}
	})
	return out
}

func sortRefs(refs []Ref) {
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Object < b.Object
	})
}

func sortFlows(flows []Flow) {
	sort.Slice(flows, func(i, j int) bool {
		a, b := flows[i], flows[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.OriginObject+a.SlotObject < b.OriginObject+b.SlotObject
	})
}
