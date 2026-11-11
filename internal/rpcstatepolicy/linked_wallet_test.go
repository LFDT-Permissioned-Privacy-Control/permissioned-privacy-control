package rpcstatepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	m "privacy-proxy/internal/rpcmetadatapolicy"
	"strings"
	"testing"
)

func TestLinkedWalletFlagIndependentGoldenAndOldFalseBytes(t *testing.T) {
	var old struct {
		Raw, DefinitionSHA, EffectiveSHA string
		MethodSet                        struct {
			Version string
			Methods []m.Method
		}
	}
	raw, err := os.ReadFile("testdata/digests-v1.json")
	if err != nil || json.Unmarshal(raw, &old) != nil {
		t.Fatal(err)
	}
	var enabled struct{ Raw, RawSHA, DefinitionSHA, EffectiveSHA string }
	raw, err = os.ReadFile("testdata/linked-wallet-digests-v1.json")
	if err != nil || json.Unmarshal(raw, &enabled) != nil {
		t.Fatal(err)
	}
	text := func(d Digest) string { return "sha256:" + hex.EncodeToString(d[:]) }
	if text(Digest(sha256.Sum256([]byte(enabled.Raw)))) != enabled.RawSHA {
		t.Fatal("independent raw hash")
	}
	definition, err := Compile([]byte(enabled.Raw), Digest(sha256.Sum256([]byte(enabled.Raw))))
	if err != nil || !definition.LinkedWalletBasicsEnabled() || text(definition.digest) != enabled.DefinitionSHA {
		t.Fatal("independent true-flag definition", err)
	}
	policy, err := Bind(definition, definition.ManifestDigest(), old.MethodSet.Version, old.MethodSet.Methods)
	if err != nil || text(policy.Digest()) != enabled.EffectiveSHA || enabled.EffectiveSHA == old.EffectiveSHA {
		t.Fatal("true permission not bound", err)
	}
	for _, source := range []string{old.Raw, strings.Replace(enabled.Raw, `"linkedWalletBasics": true`, `"linkedWalletBasics": false`, 1)} {
		d, err := Compile([]byte(source), Digest(sha256.Sum256([]byte(source))))
		if err != nil || d.LinkedWalletBasicsEnabled() || text(d.digest) != old.DefinitionSHA {
			t.Fatal("absent/false definition bytes changed", err)
		}
		p, err := Bind(d, d.ManifestDigest(), old.MethodSet.Version, old.MethodSet.Methods)
		if err != nil || text(p.Digest()) != old.EffectiveSHA {
			t.Fatal("absent/false effective bytes changed", err)
		}
	}
	for _, value := range []string{`null`, `"true"`, `[]`, `{}`, `true,"linkedWalletBasics":false`, `true,"LinkedWalletBasics":true`} {
		bad := strings.Replace(enabled.Raw, `"linkedWalletBasics": true`, `"linkedWalletBasics": `+value, 1)
		if d, err := Compile([]byte(bad), Digest(sha256.Sum256([]byte(bad)))); err == nil || d != nil {
			t.Fatal("invalid optional boolean admitted", value)
		}
	}
}
