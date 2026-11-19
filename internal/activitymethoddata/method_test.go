package activitymethoddata

import (
	"strings"
	"testing"
)

func TestClosedExplorerNamespaceAndLegacyRPCGrammar(t *testing.T) {
	labels := ExplorerLabels()
	if len(labels) != 38 {
		t.Fatal("closed route/transport label count")
	}
	for _, label := range labels {
		if Classify(label) != Explorer || Classify(strings.ToUpper(label)) != Unknown {
			t.Fatal("exact reserved namespace", label)
		}
	}
	labels[0] = "changed"
	if ExplorerLabels()[0] == "changed" {
		t.Fatal("mutable global labels")
	}
	for _, method := range []string{"method0", "eth_call", "rpc.invalid_request", "Bank.method_3"} {
		if Classify(method) != RPC {
			t.Fatal("valid old RPC lost", method)
		}
	}
	for _, method := range []string{"explorer.unknown", "Explorer.stats", "EXPLORER.unknown", "1bad", "a|b", "", "a\n", strings.Repeat("a", 101)} {
		if Classify(method) != Unknown {
			t.Fatal("unknown/invalid method accepted", method)
		}
	}
	if ClassifierDigest() == ([32]byte{}) || RPCPredicateDigest() == RequestPredicateDigest() {
		t.Fatal("population bindings collapsed")
	}
}

func TestOperationalCompletionHasNoPublicRouteAndStaysOutsideRPC(t *testing.T) {
	if got := OperationalLabels(); len(got) != 1 || got[0] != AdminAccessLogs || Classify(got[0]) != Explorer || !Reserved(got[0]) {
		t.Fatal("closed operational completion", got)
	}
	for _, operation := range Operations() {
		if operation.Label == AdminAccessLogs || operation.Route == "/admin_access_logs" {
			t.Fatal("administrative completion acquired a public Explorer route")
		}
	}
	for _, label := range ExplorerLabels() {
		if label == AdminAccessLogs {
			t.Fatal("administrative completion acquired an Explorer operation binding")
		}
	}
	labels := RequestReservedLabels()
	if len(labels) != len(ExplorerLabels())+1 {
		t.Fatal("reserved population union", labels)
	}
	labels[0] = "mutated"
	if RequestReservedLabels()[0] == "mutated" {
		t.Fatal("mutable completion population")
	}
	for _, method := range []string{"explorer.admin_access_logs_extra", "Explorer.admin_access_logs", "explorer.admin_access_log"} {
		if Classify(method) != Unknown {
			t.Fatal("unknown operational completion accepted", method)
		}
	}
	// This is the legacy SQL RPC predicate, shared by its list and summary.
	if !strings.EqualFold(AdminAccessLogs[:9], "explorer.") {
		t.Fatal("legacy RPC population would include administrative reads")
	}
	legacy := ExplorerLabels()
	for i, label := range legacy {
		if label == AdminAccessLogs {
			legacy = append(legacy[:i], legacy[i+1:]...)
			break
		}
	}
	parts := [][]byte{[]byte("grammar=1..100 ASCII bytes; first=letter; rest=letter,digit,underscore,dot"), []byte("reserved=explorer.;ASCII-case-insensitive"), []byte("RPC=valid and nonreserved"), []byte("Explorer=valid and exact lower-case compiled label")}
	for _, label := range legacy {
		parts = append(parts, []byte(label))
	}
	old := framed(Version, parts...)
	if old == ClassifierDigest() || framed("ops.activity.population-predicate/v2", []byte(PopulationRPC), old[:], []byte(RPCPredicateID)) == RPCPredicateDigest() || framed("ops.activity.population-predicate/v2", []byte(PopulationRequests), old[:], []byte(RequestPredicateID)) == RequestPredicateDigest() {
		t.Fatal("old population-bound cursors were not invalidated")
	}
}
