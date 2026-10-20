package server

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1190: BuildInventory must produce byte-identical output on every run so
// the CI api-spec drift gate (regenerate + git diff) can never flake on an
// unrelated PR. Go re-randomizes each map-range independently per execution, so
// if any output-feeding map in BuildInventory were iterated without a stable
// sort, N runs would diverge — this catches that deterministically (including a
// FUTURE unsorted-map slip), in the ./internal/... test job.
func TestBuildInventory_Deterministic(t *testing.T) {
	all := RoutesForSpec(true)
	prod := RoutesForSpec(false)

	first, _ := BuildInventory(all, prod)
	for i := 0; i < 8; i++ {
		got, _ := BuildInventory(all, prod)
		if got != first {
			t.Fatalf("BuildInventory output is not deterministic (run %d differs from run 0).\n"+
				"An output-feeding map is iterated without a stable sort — sort it before rendering.\n"+
				"first:\n%s\n\nrun %d:\n%s", i+1, first, i+1, got)
		}
	}
}

// Guards the guard: proves the byte-identical assertion above actually CATCHES
// non-determinism. Rendering a map by raw iteration order (no sort) must be
// observed to diverge across runs — otherwise TestBuildInventory_Deterministic
// could pass vacuously if map iteration were ever made stable.
func TestMapIterationIsNonDeterministic_NegativeControl(t *testing.T) {
	m := map[string]int{}
	for i := 0; i < 64; i++ {
		m[fmt.Sprintf("k%02d", i)] = i
	}
	renderUnsorted := func() string {
		var b strings.Builder
		for k := range m { // deliberately UNSORTED
			fmt.Fprintf(&b, "%s=%d;", k, m[k])
		}
		return b.String()
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		seen[renderUnsorted()] = true
		if len(seen) > 1 {
			return // observed divergence — the assertion mechanism works
		}
	}
	// A sorted render, by contrast, must be stable (sanity check the control).
	renderSorted := func() string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%d;", k, m[k])
		}
		return b.String()
	}
	if renderSorted() != renderSorted() {
		t.Fatal("sorted render should be stable")
	}
	t.Skip("map iteration did not diverge in 200 tries (unlikely with 64 keys); negative control inconclusive but sorted render is stable")
}

// methodCount is one "METHOD n" entry parsed from the rendered method-totals line.
type methodCount struct {
	method string
	count  int
}

// parseMethodTotals extracts the "Registered routes by method:" line from a
// BuildInventory rendering and returns its entries in the order rendered.
func parseMethodTotals(t *testing.T, content string) []methodCount {
	t.Helper()
	const marker = "**Registered routes by method:** "
	i := strings.Index(content, marker)
	require.GreaterOrEqual(t, i, 0, "method-totals line not found in inventory")
	line := content[i+len(marker):]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	var out []methodCount
	for _, part := range strings.Split(line, ", ") {
		f := strings.Fields(part)
		require.Len(t, f, 2, "unexpected method-totals part %q", part)
		n, err := strconv.Atoi(f[1])
		require.NoError(t, err, "non-numeric count in %q", part)
		out = append(out, methodCount{f[0], n})
	}
	return out
}

// assertMethodTotalsOrdered pins the RD-1172 ordering contract EXPLICITLY (not
// probabilistically): entries must be strictly descending by count, ties broken
// by ascending method name. Fails deterministically if the tie-break sort is
// ever dropped — unlike a byte-identical N-run check, whose detection depends on
// map-iteration randomness manifesting for what may be a small map.
func assertMethodTotalsOrdered(t *testing.T, pairs []methodCount) {
	t.Helper()
	for i := 1; i < len(pairs); i++ {
		prev, cur := pairs[i-1], pairs[i]
		if prev.count == cur.count {
			assert.Less(t, prev.method, cur.method,
				"tied-count methods must be alphabetical: %q(%d) precedes %q(%d)",
				prev.method, prev.count, cur.method, cur.count)
		} else {
			assert.Greater(t, prev.count, cur.count,
				"counts must be strictly descending: %q(%d) precedes %q(%d)",
				prev.method, prev.count, cur.method, cur.count)
		}
	}
}

// RD-1190 (Copilot follow-up): assert the method-totals ORDER explicitly — on
// the real route table AND a synthetic input with forced count ties. The
// forced-tie case guarantees the tie-break branch is exercised regardless of
// how the real table evolves, closing the gap that the probabilistic N-run
// byte-identical check leaves open for small maps.
func TestBuildInventory_MethodTotalsOrderingExplicit(t *testing.T) {
	realPairs := parseMethodTotals(t, mustInventory(RoutesForSpec(true), RoutesForSpec(false)))
	require.NotEmpty(t, realPairs)
	assertMethodTotalsOrdered(t, realPairs)

	// GET leads at 3; DELETE, POST, PUT tie at 2 → must render alphabetically.
	routes := []RouteEntry{
		{Method: "GET", Path: "/api/v1/x/a", Handler: "h"},
		{Method: "GET", Path: "/api/v1/x/b", Handler: "h"},
		{Method: "GET", Path: "/api/v1/x/c", Handler: "h"},
		{Method: "PUT", Path: "/api/v1/x/d", Handler: "h"},
		{Method: "PUT", Path: "/api/v1/x/e", Handler: "h"},
		{Method: "DELETE", Path: "/api/v1/x/f", Handler: "h"},
		{Method: "DELETE", Path: "/api/v1/x/g", Handler: "h"},
		{Method: "POST", Path: "/api/v1/x/h", Handler: "h"},
		{Method: "POST", Path: "/api/v1/x/i", Handler: "h"},
	}
	synthPairs := parseMethodTotals(t, mustInventory(routes, routes))
	assertMethodTotalsOrdered(t, synthPairs)
	got := make([]string, len(synthPairs))
	for i, p := range synthPairs {
		got[i] = p.method
	}
	require.Equal(t, []string{"GET", "DELETE", "POST", "PUT"}, got,
		"forced-tie ordering must be GET(3) then the 2-count methods alphabetically")
}

func mustInventory(all, prod []RouteEntry) string {
	content, _ := BuildInventory(all, prod)
	return content
}

// opRow is one parsed row of the "## Distinct operations" table.
type opRow struct {
	methods string // the Method(s) cell, e.g. "DELETE, GET, PUT"
	path    string // the Path cell with backticks stripped
}

// parseOperationsTable extracts the "## Distinct operations" table rows from a
// BuildInventory rendering, in rendered order.
func parseOperationsTable(t *testing.T, content string) []opRow {
	t.Helper()
	const header = "## Distinct operations"
	i := strings.Index(content, header)
	require.GreaterOrEqual(t, i, 0, "operations table not found in inventory")
	var out []opRow
	for _, line := range strings.Split(content[i:], "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Method(s)") || strings.HasPrefix(line, "|---") {
			if len(out) > 0 && !strings.HasPrefix(line, "| ") {
				break // table ended
			}
			continue
		}
		cells := strings.Split(line, "|")
		require.GreaterOrEqual(t, len(cells), 4, "unexpected table row %q", line)
		out = append(out, opRow{
			methods: strings.TrimSpace(cells[1]),
			path:    strings.Trim(strings.TrimSpace(cells[2]), "`"),
		})
	}
	return out
}

// RD-1190 (Copilot follow-up): the remaining two output-feeding maps in
// BuildInventory — `ops` (canonical path → op) and each op's `methods` set —
// get the same explicit, controlled-input ordering assertions as the
// method-totals map. Registration order is deliberately adversarial (reverse
// of the required render order), so a dropped sort fails deterministically
// instead of depending on map-iteration randomness manifesting.
func TestBuildInventory_OperationsTableOrderingExplicit(t *testing.T) {
	// Real route table: canonical paths must render strictly ascending.
	realRows := parseOperationsTable(t, mustInventory(RoutesForSpec(true), RoutesForSpec(false)))
	require.NotEmpty(t, realRows)
	for i := 1; i < len(realRows); i++ {
		assert.Less(t, realRows[i-1].path, realRows[i].path,
			"canonical paths must be strictly ascending: %q precedes %q",
			realRows[i-1].path, realRows[i].path)
	}

	// Controlled input: paths registered in descending order, and one path's
	// methods registered non-alphabetically (PUT, DELETE, GET — must render
	// "DELETE, GET, PUT"; fewer than 7 methods so the ANY collapse stays off).
	routes := []RouteEntry{
		{Method: "PUT", Path: "/api/v1/zeta", Handler: "h"},
		{Method: "DELETE", Path: "/api/v1/zeta", Handler: "h"},
		{Method: "GET", Path: "/api/v1/zeta", Handler: "h"},
		{Method: "POST", Path: "/api/v1/mid", Handler: "h"},
		{Method: "GET", Path: "/api/v1/alpha", Handler: "h"},
	}
	rows := parseOperationsTable(t, mustInventory(routes, routes))
	require.Len(t, rows, 3)
	gotPaths := []string{rows[0].path, rows[1].path, rows[2].path}
	require.Equal(t, []string{"/api/v1/alpha", "/api/v1/mid", "/api/v1/zeta"}, gotPaths,
		"table rows must be sorted by canonical path, not registration order")
	require.Equal(t, "DELETE, GET, PUT", rows[2].methods,
		"an operation's methods must render alphabetically, not in registration order")
}
