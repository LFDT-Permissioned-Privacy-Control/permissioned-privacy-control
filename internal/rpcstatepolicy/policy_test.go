package rpcstatepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	m "privacy-proxy/internal/rpcmetadatapolicy"
)

func TestStatePolicyIndependentPublicDigestGoldenAndClosedSource(t *testing.T) {
	var f struct {
		Raw, RawSHA, DefinitionSHA, MethodSetSHA, EffectiveSHA string
		MethodSet                                              struct {
			Version string
			Methods []m.Method
		}
	}
	raw, err := os.ReadFile("testdata/digests-v1.json")
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal(err)
	}
	text := func(d Digest) string { return "sha256:" + hex.EncodeToString(d[:]) }
	rawSHA := Digest(sha256.Sum256([]byte(f.Raw)))
	if text(rawSHA) != f.RawSHA {
		t.Fatal("raw golden")
	}
	definition, err := Compile([]byte(f.Raw), rawSHA)
	if err != nil || text(definition.digest) != f.DefinitionSHA {
		t.Fatal("definition golden", err)
	}
	policy, err := Bind(definition, definition.ManifestDigest(), f.MethodSet.Version, f.MethodSet.Methods)
	if err != nil || text(policy.Digest()) != f.EffectiveSHA || len(policy.Methods()) != 5 {
		t.Fatal("effective state/method golden", err)
	}
	_, methodDigest, err := m.BindMethods(f.MethodSet.Version, f.MethodSet.Methods)
	if err != nil || text(methodDigest) != f.MethodSetSHA {
		t.Fatal("shared actual full method map changed", err)
	}
	pre := definition.PreRegisteredAddresses()
	pre[0].OrganizationID = "mutated"
	methods := policy.Methods()
	methods[0].Name = "mutated"
	if definition.PreRegisteredAddresses()[0].OrganizationID == "mutated" || policy.Methods()[0].Name == "mutated" {
		t.Fatal("policy getters expose authority")
	}
	for _, bad := range []string{
		strings.Replace(f.Raw, `"anonymousMethods": [`, `"anonymousMethods":null,"extra": [`, 1),
		strings.Replace(f.Raw, `"eth_getBalance"`, `"eth_getProof"`, 1),
		strings.Replace(f.Raw, `"eth_getBalance"`, `"eth_getStorageAt"`, 1),
		strings.Replace(f.Raw, `"eth_getBalance"`, `"ETH_GETCODE"`, 1),
		strings.Replace(f.Raw, `"kind": "StatePolicy",`, `"kind":"StatePolicy","kind":"StatePolicy",`, 1),
		strings.Replace(f.Raw, `"preRegisteredAddresses": [`, `"PreRegisteredAddresses": [`, 1),
		strings.Replace(f.Raw, `"organizationId":`, `"extra":`, 1),
		strings.Replace(f.Raw, strings.Repeat("1", 64), strings.Repeat("0", 64), 1),
		f.Raw + `{}`, strings.Repeat(" ", 64<<10) + f.Raw,
	} {
		if p, err := Compile([]byte(bad), Digest(sha256.Sum256([]byte(bad)))); err == nil || p != nil {
			t.Fatal("invalid state source admitted", bad[:min(len(bad), 120)])
		}
	}
	if _, err := Compile([]byte(f.Raw+" "), rawSHA); err == nil {
		t.Fatal("raw expected hash not enforced")
	}
	if _, err := Bind(definition, Digest{1}, f.MethodSet.Version, f.MethodSet.Methods); err == nil {
		t.Fatal("foreign manifest")
	}
}
