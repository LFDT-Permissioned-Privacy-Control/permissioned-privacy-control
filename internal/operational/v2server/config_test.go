package v2server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedRuntimeSelectionIsClosedBeforeOpeningServices(t *testing.T) {
	c := Config{APIVersion: "ops.server/v2", Kind: "OperationalServer", Listen: "127.0.0.1:8443", TLSCertificateFile: "tls.crt", TLSPrivateKeyFile: "tls.key", WebDirectory: "frontend/dist-v2", Core: Selection{Directory: "core", ManifestDigest: "sha256:" + strings.Repeat("a", 64), Environment: "bank", ChainID: "1"}, BrokerSelection: Selection{Directory: "broker", ManifestDigest: "sha256:" + strings.Repeat("b", 64), Environment: "bank", ChainID: "1"}, Broker: Broker{DeploymentID: "broker", RecoveryEpoch: "11111111-1111-1111-1111-111111111111", AppDSNEnv: "BROKER_APP_DSN", ProofDSNEnv: "BROKER_PROOF_DSN", SigningPrivateKeyEnv: "BROKER_SIGNING_KEY"}, Wallet: Wallet{AppDSNEnv: "WALLET_APP_DSN", ServiceOrigin: "https://ops.test", DeploymentID: "wallet", GenesisHash: "0x" + strings.Repeat("1", 64), Generation: "11111111-1111-1111-1111-111111111111", CoverageDigest: "sha256:" + strings.Repeat("c", 64)}, SSO: SSO{AppDSNEnv: "SSO_APP_DSN", RecoveryEpoch: "11111111-1111-1111-1111-111111111111", Clients: File{"clients.json", "sha256:" + strings.Repeat("d", 64)}, Runtime: File{"sso.json", "sha256:" + strings.Repeat("e", 64)}}}
	c.Data.Nodes = []Node{}
	c.Protected.Nodes = []ProtectedNode{}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "runtime.json")
	check := func(b []byte) (Config, error) {
		t.Helper()
		if err := os.WriteFile(file, b, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return ReadConfig(file, "sha256:"+hex.EncodeToString(sum[:]))
	}
	got, err := check(raw)
	if err != nil || got.Broker.AppDSNEnv != c.Broker.AppDSNEnv {
		t.Fatal("valid deployment selection", err)
	}
	for _, bad := range [][]byte{[]byte(strings.Replace(string(raw), `"kind":"OperationalServer"`, `"kind":"OperationalServer","kind":"OperationalServer"`, 1)), []byte(strings.Replace(string(raw), `"kind":"OperationalServer"`, `"kind":"OperationalServer","users":[]`, 1)), append(append([]byte{}, raw...), []byte(`{}`)...)} {
		if _, err := check(bad); err == nil {
			t.Fatal("ambiguous or mutable-authority configuration accepted")
		}
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(file, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("unpinned runtime configuration accepted")
	}
}
