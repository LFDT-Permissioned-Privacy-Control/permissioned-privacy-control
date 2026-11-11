package rpcmetadatapolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

type digestFixture struct {
	Raw, RawSHA, DefinitionSHA, MethodSetSHA, EffectiveSHA string
	MethodSet                                              struct {
		Version string
		Methods []Method
	}
	DenyAnonymousSource Source
	DenyAnonymousSHA    string
	Alias               struct {
		ExtraMethod  Method `json:"extra_method"`
		MethodSetSHA string `json:"method_set_sha256"`
		EffectiveSHA string `json:"effective_sha256"`
	}
}

func policyFixture(t *testing.T) digestFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/digests-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f digestFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}
func digestText(d Digest) string { return "sha256:" + hex.EncodeToString(d[:]) }
func compileFixture(t *testing.T, f digestFixture) *Definition {
	t.Helper()
	d, err := Compile([]byte(f.Raw), Digest(sha256.Sum256([]byte(f.Raw))))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPolicyPublicIndependentDigestGoldens(t *testing.T) {
	f := policyFixture(t)
	rawDigest := Digest(sha256.Sum256([]byte(f.Raw)))
	if digestText(rawDigest) != f.RawSHA {
		t.Fatal("raw golden mismatch")
	}
	d := compileFixture(t, f)
	if digestText(d.Digest()) != f.DefinitionSHA {
		t.Fatal("definition golden mismatch", digestText(d.Digest()))
	}
	p, err := Bind(d, d.ManifestDigest(), f.MethodSet.Version, f.MethodSet.Methods)
	if err != nil || digestText(p.MethodSetDigest()) != f.MethodSetSHA || digestText(p.Digest()) != f.EffectiveSHA {
		t.Fatal("full method/effective golden mismatch", p, err)
	}
	methods := append(slices.Clone(f.MethodSet.Methods), f.Alias.ExtraMethod)
	changed, err := Bind(d, d.ManifestDigest(), f.MethodSet.Version, methods)
	if err != nil || digestText(changed.MethodSetDigest()) != f.Alias.MethodSetSHA || digestText(changed.Digest()) != f.Alias.EffectiveSHA || changed.Digest() == p.Digest() {
		t.Fatal("same-version actual alias/claim map not bound", changed, err)
	}
	raw, _ := json.Marshal(f.DenyAnonymousSource)
	deny, err := Compile(raw, Digest(sha256.Sum256(raw)))
	if err != nil || digestText(deny.Digest()) != f.DenyAnonymousSHA {
		t.Fatal("explicit deny-all golden mismatch", deny, err)
	}
	denied, err := Bind(deny, deny.ManifestDigest(), f.MethodSet.Version, f.MethodSet.Methods)
	if err != nil || denied.AllowsAnonymous("eth_chainId") || len(deny.AnonymousMethods()) != 0 {
		t.Fatal("explicit [] granted anonymous", err)
	}
}

func TestPolicyClosedSourceAndPinnedRawBytes(t *testing.T) {
	f := policyFixture(t)
	for _, raw := range []string{
		strings.Replace(f.Raw, `"anonymousMethods": [`, `"AnonymousMethods": [`, 1),
		strings.Replace(f.Raw, `"anonymousMethods": [`, `"anonymousMethods":null,"extra": [`, 1),
		strings.Replace(f.Raw, `"kind": "MetadataPolicy",`, `"kind": "MetadataPolicy","kind":"MetadataPolicy",`, 1),
		strings.Replace(f.Raw, `"web3_clientVersion"`, `"eth_getProof"`, 1),
		strings.Replace(f.Raw, `"web3_clientVersion"`, `"ETH_CHAINID"`, 1),
		strings.Replace(f.Raw, `"web3_clientVersion"`, `"eth_chainId"`, 1),
		strings.Replace(f.Raw, `"kind": "MetadataPolicy",`, `"kind":{},`, 1),
		strings.Replace(f.Raw, strings.Repeat("1", 64), strings.Repeat("0", 64), 1),
		`{"apiVersion":"ops.rpc-metadata-policy/v1","kind":"MetadataPolicy","bundleManifestDigest":"sha256:` + strings.Repeat("1", 64) + `","anonymousMethods":null}`,
		`{"apiVersion":"ops.rpc-metadata-policy/v1","kind":"MetadataPolicy","bundleManifestDigest":"sha256:` + strings.Repeat("1", 64) + `"}`,
		f.Raw + `{}`, string([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
		strings.Repeat(" ", 64<<10) + f.Raw,
	} {
		if d, err := Compile([]byte(raw), Digest(sha256.Sum256([]byte(raw)))); err == nil || d != nil {
			t.Fatalf("invalid source accepted: %q", raw[:min(len(raw), 100)])
		}
	}
	if d, err := Compile([]byte(f.Raw), Digest{}); err == nil || d != nil {
		t.Fatal("zero expected raw SHA accepted")
	}
	if d, err := Compile([]byte(f.Raw+" "), Digest(sha256.Sum256([]byte(f.Raw)))); err == nil || d != nil {
		t.Fatal("changed pinned bytes accepted")
	}
}

func TestPolicyOwnedMethodsAndClosedAliasStructure(t *testing.T) {
	f := policyFixture(t)
	d := compileFixture(t, f)
	methods := append(slices.Clone(f.MethodSet.Methods), f.Alias.ExtraMethod)
	p, err := Bind(d, d.ManifestDigest(), f.MethodSet.Version, methods)
	if err != nil {
		t.Fatal(err)
	}
	methods[len(methods)-1].RequiredClaims[0] = "upgrade"
	get := p.MetadataMethods()
	if get[0].Name != "bank_chainId" || !slices.Equal(get[0].RequiredClaims, []string{"admin"}) || len(get) != 13 {
		t.Fatal("method input aliases or wrong metadata subset", get)
	}
	get[0].RequiredClaims[0] = "deploy"
	anonymous := d.AnonymousMethods()
	anonymous[0] = "eth_accounts"
	if !p.AllowsAnonymous("eth_chainId") || p.AllowsAnonymous("bank_chainId") || p.MetadataMethods()[0].RequiredClaims[0] != "admin" {
		t.Fatal("getter aliases authority storage")
	}
	for _, extra := range []Method{
		{Name: "bank_unknown", Canonical: "missing_target"},
		{Name: "bank_child", Canonical: "bank_chainId"},
		{Name: "eth_chainId", Canonical: "eth_chainId"},
		{Name: "bank_bad", Canonical: "eth_chainId", RequiredClaims: []string{"kyc"}},
		{Name: "bank_bad", Canonical: "eth_chainId", RequiredClaims: []string{"admin", "admin"}},
	} {
		if _, err := Bind(d, d.ManifestDigest(), f.MethodSet.Version, append(slices.Clone(f.MethodSet.Methods), f.Alias.ExtraMethod, extra)); err == nil {
			t.Fatal("invalid/duplicate method structure accepted", extra)
		}
	}
	if _, err := Bind(d, Digest{2}, f.MethodSet.Version, f.MethodSet.Methods); err == nil {
		t.Fatal("foreign manifest bound")
	}
	var absent *Policy
	if absent.AllowsAnonymous("eth_chainId") || absent.Digest() != (Digest{}) || absent.MethodSetDigest() != (Digest{}) {
		t.Fatal("zero policy created authority")
	}
}
