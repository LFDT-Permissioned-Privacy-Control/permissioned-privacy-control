package v2demo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	core "github.com/iden3/go-iden3-core/v2"
	"math/big"
	"os"
	"path/filepath"
	"privacy-proxy/internal/operational/ssohttp"
	vs "privacy-proxy/internal/operational/v2server"
	"privacy-proxy/internal/ssopolicy"
	"slices"
	"testing"
)

func publicDID(t *testing.T, index int64) string {
	t.Helper()
	typ, e := core.BuildDIDType(core.DIDMethodIden3, core.Polygon, core.Mumbai)
	if e != nil {
		t.Fatal(e)
	}
	id, e := core.NewIDFromIdenState(typ, new(big.Int).Lsh(big.NewInt(index), 40))
	if e != nil {
		t.Fatal(e)
	}
	did, e := core.ParseDIDFromID(*id)
	if e != nil {
		t.Fatal(e)
	}
	return did.String()
}
func TestInitPersistsIdentityAuthorityAndNativeRevision(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if e := Init(root); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(root, "private/state.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(root, "compose.env")); e != nil {
		t.Fatal(e)
	}
	if e = Init(root); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, "compose.env")); e != nil {
		t.Fatal("interrupted derived init tail was not recovered", e)
	}
	after, _ := os.ReadFile(filepath.Join(root, "private/state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("ordinary init changed persisted keys/ports/epochs")
	}
	s, e := readState(root)
	if e != nil {
		t.Fatal(e)
	}
	if s.rolePassword("demo_wallet_app") == s.rolePassword("demo_wallet_reader") {
		t.Fatal("roles shared credentials")
	}
	leafBytes, e := os.ReadFile(s.file("tls.crt"))
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(leafBytes)
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil || leaf.IsCA {
		t.Fatal("serving certificate retained CA authority", e)
	}
	caBytes, _ := os.ReadFile(s.file("ca.crt"))
	block, _ = pem.Decode(caBytes)
	ca, e := x509.ParseCertificate(block.Bytes)
	if e != nil || leaf.CheckSignatureFrom(ca) != nil {
		t.Fatal("owned CA did not sign serving leaf", e)
	}
	if _, e = os.Stat(s.file("private/ca.key")); e != nil {
		t.Fatal(e)
	}
	contextBytes := []byte(`{"@context":{"@version":1.1,"BankRole":{"@id":"https://schemas.test/BankRole","@context":{"role":{"@id":"https://schemas.test/role","@type":"http://www.w3.org/2001/XMLSchema#integer"}}}}}`)
	sum := sha256.Sum256(contextBytes)
	m := WalletMetadata{Version: 1, TestOnly: true, Network: "polygon:mumbai", ChainID: "80001", StateContract: "0x1111111111111111111111111111111111111111", StateRPCURL: s.WalletOrigin() + "/rpc", IssuerDID: publicDID(t, 10), VerifierDID: publicDID(t, 11), ContextURL: "https://schemas.test/role.jsonld", ContextPath: "role-context.json", ContextSHA256: "sha256:" + hex.EncodeToString(sum[:]), CredentialType: "BankRole", CircuitID: "credentialAtomicQuerySigV2", Personas: []Persona{}}
	for i, id := range []string{"admin", "deployer", "reader", "outsider"} {
		who := Persona{ID: id, HolderDID: publicDID(t, int64(20+i)), ProfileID: "demo-" + id}
		if i < 3 {
			value := i + 1
			who.RoleValue = &value
		}
		m.Personas = append(m.Personas, who)
	}
	if _, e = writeBytes(s.file("wallet-state/role-context.json"), contextBytes); e != nil {
		t.Fatal(e)
	}
	if _, e = writeJSON(s.file("wallet-state/metadata.json"), m); e != nil {
		t.Fatal(e)
	}
	current, broker, selection, bs, e := bundles(context.Background(), s)
	if e != nil {
		t.Fatal("actual native approved prepare/load", e)
	}
	ids, _ := current.Identity()
	brokerIDs, _ := broker.Identity()
	if ids.Digest() != brokerIDs.Digest() {
		t.Fatal("Core/broker identities diverged")
	}
	auth, _ := broker.AuthBroker()
	source, _ := auth.MultiSource()
	if len(source.AzureProfiles) != 0 || len(source.PrivadoProfiles) != 4 {
		t.Fatal("demo requested hosted auth or omitted identities")
	}
	for _, id := range []string{Admin, Deployer} {
		group, ok := current.Group(Organization, id)
		if !ok || !slices.Contains(group.AllowedMethods, "eth_sendTransaction") {
			t.Fatal("signed raw send lost its V1-compatible capability")
		}
	}
	cfg := vs.Config{}
	if e = runtimeFiles(context.Background(), s, current, broker, &cfg); e != nil {
		t.Fatal("publish runtime files", e)
	}
	published, e := os.ReadFile(cfg.SSO.Clients.Path)
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := ssopolicy.Compile(published, ids, references{current})
	if e != nil {
		t.Fatal(e)
	}
	runtimeBytes, e := os.ReadFile(cfg.SSO.Runtime.Path)
	if e != nil {
		t.Fatal(e)
	}
	var runtime ssohttp.RuntimeSource
	if json.Unmarshal(runtimeBytes, &runtime) != nil || runtime.ClientCatalogDigest != catalog.Digest() {
		t.Fatal("runtime pin does not match exact published client bytes")
	}
	s.ReaderGrant = false
	changed, sameBroker, newSelection, newBS, e := bundles(context.Background(), s)
	if e != nil {
		t.Fatal("actual revision", e)
	}
	nextIDs, _ := changed.Identity()
	if selection.ManifestDigest == newSelection.ManifestDigest || bs.ManifestDigest != newBS.ManifestDigest || sameBroker.Metadata().ManifestDigest != broker.Metadata().ManifestDigest || ids.Digest() != nextIDs.Digest() {
		t.Fatal("permission revision changed identity/broker or failed to change rules")
	}
}
