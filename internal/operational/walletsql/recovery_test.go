package walletsql

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	f "privacy-proxy/internal/disclosuretest"
	w "privacy-proxy/internal/walletops"
)

func batchFixture(t *testing.T) (RevocationBatch, w.Namespace) {
	t.Helper()
	binding := w.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 64), DeploymentID: "test"}
	ns, err := binding.Namespace()
	if err != nil {
		t.Fatal(err)
	}
	return RevocationBatch{APIVersion: "ops.wallet-revocations/v1", Kind: "WalletRevocationBatch", Namespace: ns.String(), SourceExportDigest: DigestString(sha256.Sum256([]byte("source"))), Aliases: []Alias{{LegacySubject: "did:source:a", ActorID: f.Actor(f.Subject), EvidenceDigest: DigestString(sha256.Sum256([]byte("alias"))), IdentityAuthority: "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", SourceTenant: f.Tenant, SourceKind: "human"}}, Revocations: []Revocation{{LegacySubject: "did:source:a", Address: "0x" + strings.Repeat("a", 40), RevokedAt: time.Unix(f.Now-1, 0).UTC().Format(time.RFC3339)}}}, ns
}
func TestStrictRevocationImportAndAliasCoalescing(t *testing.T) {
	b, ns := batchFixture(t)
	raw, _ := json.Marshal(b)
	if _, rows, err := decodeBatch(raw, ns); err != nil || len(rows) != 1 {
		t.Fatal("valid batch", err)
	}
	for _, mutate := range []func(*RevocationBatch){
		func(b *RevocationBatch) { b.Namespace = NamespaceStringDifferent(ns) },
		func(b *RevocationBatch) { b.Revocations[0].LegacySubject = "unknown" },
		func(b *RevocationBatch) { b.Revocations[0].Address = "0x" + strings.Repeat("A", 40) },
		func(b *RevocationBatch) { b.Aliases[0].ActorID = "did:legacy:a" },
		func(b *RevocationBatch) { b.Aliases[0].SourceKind = "admin" },
		func(b *RevocationBatch) { b.Aliases[0].SourceTenant = "" },
		func(b *RevocationBatch) { b.Aliases[0].SourceTenant = f.Subject },
		func(b *RevocationBatch) {
			b.Aliases[0].IdentityAuthority = "https://login.microsoftonline.com/common/v2.0"
		},
		func(b *RevocationBatch) { b.Aliases[0].IdentityAuthority = "https://identity.test" },
		func(b *RevocationBatch) {
			b.Aliases[0].IdentityAuthority = "privado"
			b.Aliases[0].SourceTenant = ""
			b.Aliases[0].SourceKind = "service"
		},
		func(b *RevocationBatch) {
			b.Aliases[0].IdentityAuthority = "privado"
			b.Aliases[0].SourceKind = "human"
		},
		func(b *RevocationBatch) { b.Aliases[0].EvidenceDigest = "sha256:bad" },
		func(b *RevocationBatch) { b.Aliases = append(b.Aliases, b.Aliases[0]) },
		func(b *RevocationBatch) { b.Revocations = append(b.Revocations, b.Revocations[0]) },
		func(b *RevocationBatch) { b.Revocations[0].RevokedAt = "2026-11-07T00:00:00+00:00" },
		func(b *RevocationBatch) { b.Aliases = nil },
	} {
		var changed RevocationBatch
		_ = json.Unmarshal(raw, &changed)
		mutate(&changed)
		encoded, _ := json.Marshal(changed)
		if _, _, err := decodeBatch(encoded, ns); err == nil {
			t.Fatal("unsafe batch accepted", string(encoded))
		}
	}
	for _, bad := range [][]byte{bytesReplace(raw, `"kind":`, `"Kind":`), bytesReplace(raw, `"kind":`, `"unknown":1,"kind":`), bytesReplace(raw, `"kind":`, `"kind":"duplicate","kind":`), append(append([]byte{}, raw...), []byte(`{}`)...)} {
		if _, _, err := decodeBatch(bad, ns); err == nil {
			t.Fatal("nonclosed JSON accepted")
		}
	}
	second := b.Aliases[0]
	second.LegacySubject = "did:source:b"
	b.Aliases = append(b.Aliases, second)
	r := b.Revocations[0]
	r.LegacySubject = second.LegacySubject
	r.RevokedAt = time.Unix(f.Now-20, 0).UTC().Format(time.RFC3339)
	b.Revocations = append(b.Revocations, r)
	encoded, _ := json.Marshal(b)
	_, rows, err := decodeBatch(encoded, ns)
	if err != nil || len(rows) != 1 || rows[0].at.Unix() != f.Now-20 {
		t.Fatal("aliases not coalesced at earliest revocation", err)
	}
}

func TestSupportedAliasFamiliesAreStructuralAttestations(t *testing.T) {
	b, ns := batchFixture(t)
	for _, a := range []Alias{
		b.Aliases[0],
		{LegacySubject: "service:opaque", ActorID: f.Actor(f.Subject), EvidenceDigest: b.Aliases[0].EvidenceDigest, IdentityAuthority: b.Aliases[0].IdentityAuthority, SourceTenant: f.Tenant, SourceKind: "service"},
		{LegacySubject: "did:iden3:opaque", ActorID: f.Actor(f.Subject), EvidenceDigest: b.Aliases[0].EvidenceDigest, IdentityAuthority: "privado", SourceTenant: "", SourceKind: "human"},
	} {
		b.Aliases = []Alias{a}
		b.Revocations[0].LegacySubject = a.LegacySubject
		raw, _ := json.Marshal(b)
		if _, _, err := decodeBatch(raw, ns); err != nil {
			t.Fatal("supported alias family rejected", a.IdentityAuthority, a.SourceKind, err)
		}
	}
}
func NamespaceStringDifferent(ns w.Namespace) string { ns[0] ^= 1; return ns.String() }
func bytesReplace(raw []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(raw), old, replacement, 1))
}
func TestRetentionBounds(t *testing.T) {
	if r, err := RetentionFromEnv(func(string) string { return "" }); err != nil || r.Batch != 1000 || r.Interval != time.Minute {
		t.Fatal(r, err)
	}
	for _, value := range []string{"0", "1001", "01", "-1", "not-a-number"} {
		if _, err := RetentionFromEnv(func(key string) string {
			if key == "RETENTION_WALLET_CHALLENGES_CLEANUP_BATCH" {
				return value
			}
			return ""
		}); err == nil {
			t.Fatal("invalid batch", value)
		}
	}
}
