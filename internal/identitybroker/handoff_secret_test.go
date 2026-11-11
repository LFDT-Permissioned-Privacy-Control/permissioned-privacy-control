package identitybroker

import (
	"bytes"
	"crypto/ed25519"
	f "privacy-proxy/internal/brokertest"
	"testing"
)

// Public known keys exercise key-role separation only, not provider authority.
func TestHandoffSecretRoleSeparation(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	auth, _ := snapshot.AuthBroker()
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'C'}, 32))
	mac, aes, e := newCommonKeyrings(auth.CommonSettings(), []SecretBinding{{"OPS_BROKER_REFRESH_TEST", bytes.Repeat([]byte{'A'}, 32)}}, []SecretBinding{{"OPS_BROKER_ENCRYPTION_TEST", bytes.Repeat([]byte{'B'}, 32)}}, signing)
	if e != nil {
		t.Fatal(e)
	}
	s := &Service{broker: auth, private: signing, mac: mac, aes: aes}
	ck := SecretBinding{"SSO_CONTEXT", bytes.Repeat([]byte{'D'}, 32)}
	gk := SecretBinding{"SSO_GRANT", bytes.Repeat([]byte{'E'}, 32)}
	client := SecretBinding{"SSO_CLIENT", bytes.Repeat([]byte{'F'}, 32)}
	if e = s.CheckHandoffSecrets(ck, gk, []SecretBinding{client}); e != nil {
		t.Fatal("distinct roles rejected", e)
	}
	for name, key := range map[string][]byte{"context": ck.Value, "grant": gk.Value, "broker MAC": bytes.Repeat([]byte{'A'}, 32), "broker AES": bytes.Repeat([]byte{'B'}, 32), "signing seed": signing.Seed(), "signing private": signing} {
		t.Run(name, func(t *testing.T) {
			bad := client
			bad.Value = bytes.Clone(key)
			if s.CheckHandoffSecrets(ck, gk, []SecretBinding{bad}) == nil {
				t.Fatal("cross-role bytes accepted")
			}
		})
	}
	for _, ref := range []string{ck.FromEnv, gk.FromEnv, "OPS_BROKER_REFRESH_TEST", "OPS_BROKER_ENCRYPTION_TEST"} {
		bad := client
		bad.FromEnv = ref
		if s.CheckHandoffSecrets(ck, gk, []SecretBinding{bad}) == nil {
			t.Fatal("cross-role ref with different bytes accepted", ref)
		}
	}
	duplicate := SecretBinding{"ANOTHER_CLIENT", bytes.Clone(client.Value)}
	if s.CheckHandoffSecrets(ck, gk, []SecretBinding{client, duplicate}) == nil {
		t.Fatal("cross-client bytes reused")
	}
	duplicate.Value = bytes.Repeat([]byte{'G'}, 32)
	duplicate.FromEnv = client.FromEnv
	if s.CheckHandoffSecrets(ck, gk, []SecretBinding{client, duplicate}) == nil {
		t.Fatal("cross-client ref reused")
	}
	if s.CheckHandoffSecrets(ck, gk, nil) == nil || s.CheckHandoffSecrets(ck, gk, make([]SecretBinding, 129)) == nil {
		t.Fatal("unbounded client selection accepted")
	}
}
