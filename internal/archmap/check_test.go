package archmap

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*Manifest, *Analysis) {
	t.Helper()
	m, err := Load("testdata/refmod/modules.toml")
	require.NoError(t, err)
	a, err := Analyze("testdata/refmod", AnalyzeOptions{Patterns: []string{"./..."}})
	require.NoError(t, err)
	return m, a
}

func TestAnalyzeRecordsReferencesFlowsAndInitFacts(t *testing.T) {
	_, a := fixture(t)
	refs := map[string]Ref{}
	for _, r := range a.Refs {
		refs[r.From+" "+r.Func+" -> "+r.To+" "+r.Object] = r
	}
	_, ok := refs["app/serve.go Router.Serve -> legacy/old.go Old"]
	require.True(t, ok, "the enclosing method is recorded: %v", keys(refs))
	r, ok := refs["app/serve.go  -> legacy/old.go Thing"]
	require.True(t, ok, "package-level uses have no enclosing function")
	require.False(t, r.InTypeDecl, "a composite literal in an initializer is not a type declaration")
	for _, r := range a.Refs {
		if r.From == "app/serve.go" && r.Object == "Thing" && r.Line == 31 {
			require.True(t, r.InTypeDecl, "the Holder field type is a type declaration")
		}
	}
	r, ok = refs["app/serve.go Wire -> app/serve.go Holder.L"]
	require.False(t, ok, "same-file uses are not cross-file references")

	flows := map[string]bool{}
	for _, f := range a.Flows {
		flows[f.File+" "+f.Func+": "+f.Origin+" "+f.OriginObject+" => "+f.Slot+" "+f.SlotObject] = true
	}
	require.True(t, flows["app/serve.go Wire: legacy/old.go Thing => app/serve.go Holder.L"], "%v", flows)
	require.True(t, flows["app/serve.go : legacy/old.go Old => app/serve.go hook"], "%v", flows)

	init := a.Files["legacy/init.go"]
	require.NotNil(t, init)
	require.True(t, init.Init)
	var callees []string
	for _, c := range init.InitCalls {
		callees = append(callees, c.Callee)
	}
	require.Equal(t, []string{"errors.New", "refmod/legacy.start", "function value through"}, callees, "an uncalled function literal does not run at init; a call through a variable does")
	require.Contains(t, a.Files["app/serve.go"].Decls, "Router.Serve")
	require.Contains(t, a.Files["app/serve.go"].Decls, "Holder.L")
}

func TestCheckReportsEveryBoundaryViolation(t *testing.T) {
	m, a := fixture(t)
	var got []string
	for _, v := range Check(m, a, CheckOptions{InitCallAllowlist: []string{"errors.New"}}) {
		got = append(got, v.Rule+" "+v.File+" "+v.Func+" "+v.Object)
	}
	sort.Strings(got)
	want := []string{
		"core-calls-legacy app/serve.go  Old",
		"core-calls-legacy app/serve.go  Thing",
		"core-calls-legacy app/serve.go Plain Old",
		"core-calls-legacy app/serve.go Router.Serve.func Other",
		"core-calls-legacy app/serve.go Router.Wide Other",
		"core-calls-legacy app/serve.go  Thing",
		"core-calls-legacy app/serve.go More Hidden",
		"core-calls-legacy app/serve.go More Pick",
		"core-calls-legacy app/serve.go More Thing",
		"core-calls-legacy app/serve.go More Thing.Count",
		"core-calls-legacy app/serve.go Wire New",
		"legacy-flows-into-core app/serve.go  Old => hook",
		"legacy-flows-into-core app/serve.go  Thing => d",
		"legacy-flows-into-core app/serve.go Leak Thing => Leak",
		"legacy-flows-into-core app/serve.go More Thing => More",
		"legacy-flows-into-core app/serve.go More Thing => More",
		"legacy-flows-into-core app/serve.go More Thing => ch",
		"legacy-flows-into-core app/serve.go More Thing => list",
		"legacy-flows-into-core app/serve.go Local Thing => s",
		"legacy-flows-into-core app/serve.go Wire Thing => Holder.L",
		"legacy-method-on-core-type app/legacy_part.go  Router.Describe",
		"legacy-runs-at-init app/legacy_part.go  func literal",
		"legacy-runs-at-init cmd/tool/main.go  main",
		"legacy-runs-at-init app/legacy_part.go  import _ refmod/gate",
		"legacy-runs-at-init legacy/init.go  function value through",
		"legacy-runs-at-init legacy/init.go  init",
		"legacy-runs-at-init legacy/init.go  refmod/legacy.start",
		"shipped-outside app/tool.go  tool",
		"stale-dispatch app/serve.go  Gone",
		"stale-dispatch app/serve.go Router.Serve Other",
	}
	sort.Strings(want)
	require.Equal(t, want, got, "\n%s", strings.Join(got, "\n"))
}

func TestCheckFailsClosedOnUnclassifiedDeclarations(t *testing.T) {
	m, a := fixture(t)
	m.Modules = m.Modules[1:] // drop "store": its files are now unclassified
	m.byName = map[string]*Module{}
	for _, mod := range m.Modules {
		m.byName[mod.Name] = mod
	}
	var unclassified []string
	for _, v := range Check(m, a, CheckOptions{}) {
		if v.Rule == "unclassified" {
			unclassified = append(unclassified, v.File)
		}
	}
	require.Contains(t, unclassified, "store/db.go")
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
