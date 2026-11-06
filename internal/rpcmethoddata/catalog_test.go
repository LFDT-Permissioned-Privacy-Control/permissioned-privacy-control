package rpcmethoddata_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/rpcmethoddata"
)

func TestBuiltinCatalogMatchesCapturedLegacyStartup(t *testing.T) {
	raw, err := os.ReadFile("testdata/legacy-builtins.json")
	if err != nil {
		t.Fatal(err)
	}
	var baseline struct {
		Read, Write, Trace, Blocked map[string]bool
		Assignable, Wildcard        []string
		Aliases                     map[string]string
	}
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	seed := rpcmethoddata.BuiltinCatalog()
	for name, pair := range map[string][2]any{
		"read": {baseline.Read, rpcmethoddata.ReadSet()}, "write": {baseline.Write, rpcmethoddata.WriteSet()},
		"trace": {baseline.Trace, rpcmethoddata.TraceSet()}, "blocked": {baseline.Blocked, rpcmethoddata.BlockedSet()},
		"assignable": {baseline.Assignable, seed.Assignable}, "wildcard": {baseline.Wildcard, seed.Wildcard}, "aliases": {baseline.Aliases, seed.Aliases},
		"legacy assignable": {baseline.Assignable, rbac.SupportedMethods()}, "legacy wildcard": {baseline.Wildcard, rbac.AllAllowedMethods()},
	} {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Fatalf("%s changed from pre-extraction startup: %v != %v", name, pair[0], pair[1])
		}
	}
	if seed.Version != rpcmethoddata.Version || len(seed.RequiredClaims) != 0 {
		t.Fatal("built-in version or original empty method-claim set changed")
	}
	for _, name := range []string{"eth_newFilter", "eth_getFilterChanges", "eth_sign", "personal_sign"} {
		for _, accepted := range seed.Assignable {
			if name == accepted {
				t.Fatalf("blocked method %s leaked into seed", name)
			}
		}
	}
}

func TestBuiltinCatalogIsDetachedFromCallersAndLegacyRegistration(t *testing.T) {
	before := rpcmethoddata.BuiltinCatalog()
	changed := rpcmethoddata.BuiltinCatalog()
	changed.Assignable[0] = "invented"
	changed.Wildcard[0] = "invented"
	changed.Aliases["invented"] = "eth_call"
	changed.RequiredClaims["eth_call"] = "admin"
	read := rpcmethoddata.ReadSet()
	read["invented"] = true
	delete(read, "eth_call")
	blocked := rpcmethoddata.BlockedSet()
	blocked["eth_call"] = true
	prefixes := rpcmethoddata.BlockedPrefixes()
	prefixes[0] = "eth_"
	exemptions := rpcmethoddata.BlockExemptions()
	exemptions["ops_prepare"] = true
	exact := rpcmethoddata.ExactOnly()
	exact[0] = "invented"
	if after := rpcmethoddata.BuiltinCatalog(); !reflect.DeepEqual(before, after) {
		t.Fatal("caller mutation reached compiled seed")
	}
	oldExtra, oldNamespaces, oldAliases, oldPass := rbac.ExtraMethods, rbac.ExtraNamespaces, rbac.MethodAliases, rbac.PassthroughMethods
	defer func() {
		rbac.ExtraMethods, rbac.ExtraNamespaces, rbac.MethodAliases, rbac.PassthroughMethods = oldExtra, oldNamespaces, oldAliases, oldPass
	}()
	if err := rbac.RegisterExtraNamespaces(map[string][]string{"chain": {"chain_call"}}, map[string]string{"chain_call": "eth_call"}, nil); err != nil {
		t.Fatal(err)
	}
	if !rbac.IsAssignableMethod("chain_call") {
		t.Fatal("legacy registration contract changed")
	}
	oldBlocked := rbac.GlobalBlockedMethods["eth_call"]
	rbac.GlobalBlockedMethods["eth_call"] = true
	defer func() {
		if oldBlocked {
			rbac.GlobalBlockedMethods["eth_call"] = oldBlocked
		} else {
			delete(rbac.GlobalBlockedMethods, "eth_call")
		}
	}()
	if !rbac.IsMethodBlocked("eth_call") || rpcmethoddata.IsBlocked("eth_call") {
		t.Fatal("legacy exported map is not separate from immutable seed")
	}
	if after := rpcmethoddata.BuiltinCatalog(); !reflect.DeepEqual(before, after) {
		t.Fatal("legacy registration or mutation floated the pinned seed")
	}
}

func TestBlockingMatcherKeepsExactDenyBeforePrefixExemption(t *testing.T) {
	for name, want := range map[string]bool{" OPS_prepare ": true, "ADMIN_peers": true, "debug_traceCall": false, "debug_dumpBlock": true, "eth_newFilter": true, "eth_call": false} {
		if got := rpcmethoddata.IsBlocked(name); got != want {
			t.Fatalf("%s: got%v want%v", name, got, want)
		}
	}
	if !rpcmethoddata.BlockedWith("DEBUG_TRACECALL", map[string]bool{"debug_tracecall": true}, []string{"debug_"}, map[string]bool{"debug_tracecall": true}) {
		t.Fatal("prefix exemption overrode exact deny")
	}
}
