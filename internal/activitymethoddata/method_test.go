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
