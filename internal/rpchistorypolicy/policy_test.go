package rpchistorypolicy

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func historyDefinition(t *testing.T, anonymous []string) (*Definition, []byte) {
	t.Helper()
	raw, _ := json.Marshal(Source{APIVersion: APIVersion, Kind: Kind, BundleManifestDigest: "sha256:" + strings.Repeat("ab", 32), AnonymousMethods: anonymous})
	d, err := Compile(raw, Digest(sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return d, raw
}
func TestHistoryDefinitionAnonymousIsExplicitAndOwned(t *testing.T) {
	d, _ := historyDefinition(t, []string{})
	methods := []Method{}
	for name := range historyNames {
		methods = append(methods, Method{Name: name, Canonical: name, RequiredClaims: []string{}})
	}
	methods = append(methods, Method{Name: "bank_history", Canonical: "eth_getTransactionByHash", RequiredClaims: []string{"admin"}})
	p, err := Bind(d, d.ManifestDigest(), "rpc-method-catalog/v1", methods)
	if err != nil || p.Digest() == (Digest{}) {
		t.Fatal(err)
	}
	for name := range historyNames {
		if p.AllowsAnonymous(name) {
			t.Fatal("empty declaration granted anonymous", name)
		}
	}
	allowed, _ := historyDefinition(t, []string{"eth_getBlockByNumber"})
	next, err := Bind(allowed, allowed.ManifestDigest(), "rpc-method-catalog/v1", methods)
	if err != nil || !next.AllowsAnonymous("eth_getBlockByNumber") || next.AllowsAnonymous("bank_history") || next.AllowsAnonymous("eth_getTransactionByHash") {
		t.Fatal("anonymous subset/alias widened", err)
	}
	copy := next.HistoryMethods()
	for i := range copy {
		copy[i].Name = "changed"
		if len(copy[i].RequiredClaims) > 0 {
			copy[i].RequiredClaims[0] = "changed"
		}
	}
	for _, m := range next.HistoryMethods() {
		if m.Name == "changed" || len(m.RequiredClaims) > 0 && m.RequiredClaims[0] == "changed" {
			t.Fatal("caller changed bound permissions")
		}
	}
	if _, err = Bind(d, allowed.Digest(), "rpc-method-catalog/v1", methods); err == nil {
		t.Fatal("definition/manifest mismatch bound")
	}
}
func TestHistoryDefinitionRejectsMalformedAndNonhistoryApproval(t *testing.T) {
	_, good := historyDefinition(t, []string{})
	if _, err := Compile(good, Digest{1}); err == nil {
		t.Fatal("wrong raw SHA approved")
	}
	for _, raw := range [][]byte{[]byte(strings.Replace(string(good), `"anonymousMethods":[]`, `"anonymousMethods":["eth_sendRawTransaction"]`, 1)), []byte(strings.Replace(string(good), `"anonymousMethods":[]`, `"anonymousMethods":["eth_getLogs","eth_getLogs"]`, 1)), append(append([]byte{}, good[:len(good)-1]...), []byte(`,"kind":"HistoryPolicy"}`)...), append(append([]byte{}, good...), []byte(` {}`)...), []byte(strings.Repeat(" ", 64<<10) + "{}")} {
		if _, err := Compile(raw, Digest(sha256.Sum256(raw))); err == nil {
			t.Fatal("malformed/nonhistory selection accepted")
		}
	}
	d, _ := historyDefinition(t, []string{})
	for _, methods := range [][]Method{{{Name: "bank_history", Canonical: "eth_missing"}}, {{Name: "eth_getLogs", Canonical: "eth_getLogs", RequiredClaims: []string{"owner"}}}, {{Name: "eth_getLogs", Canonical: "eth_getLogs"}, {Name: "eth_getLogs", Canonical: "eth_getLogs"}}} {
		if _, err := Bind(d, d.ManifestDigest(), "rpc-method-catalog/v1", methods); err == nil {
			t.Fatal("invalid actual method catalog bound")
		}
	}
}
