package brokertest

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core/v2"
	"privacy-proxy/internal/brokerpolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

const PrivadoProfile = "privado"
const PrivadoRoleProfile = "privado-role"
const PrivadoContextURL = "https://schemas.bank.test/role.jsonld"
const PrivadoStateContract = "0x1111111111111111111111111111111111111111"

var PrivadoContext = []byte(`{"@context":{"@version":1.1,"BankRole":{"@id":"urn:bank:role","@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","iden3_serialization":"iden3:v1:slotIndexA=role","role":{"@id":"urn:bank:role:value","@type":"http://www.w3.org/2001/XMLSchema#integer"}}}}}`)

// PublicFixtureDID constructs public synthetic genesis identities, not keys.
func PublicFixtureDID(t testing.TB, state int64) string {
	t.Helper()
	typ, err := core.BuildDIDType(core.DIDMethodIden3, core.Polygon, core.Mumbai)
	if err != nil {
		t.Fatal(err)
	}
	id, err := core.NewIDFromIdenState(typ, new(big.Int).Lsh(big.NewInt(state), 40))
	if err != nil {
		t.Fatal(err)
	}
	d, err := core.ParseDIDFromID(*id)
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}
func MultiIdentitySource(t testing.TB) identity.SourceCatalog {
	s := IdentitySource()
	sum := sha256.Sum256(PrivadoContext)
	verifier := PublicFixtureDID(t, 11)
	issuer := PublicFixtureDID(t, 12)
	s.Profiles = append(s.Profiles, identity.Profile{ID: PrivadoProfile, Kind: identity.PrivadoIdentity, VerifierID: verifier, Network: "polygon:mumbai", IdentityStateContract: PrivadoStateContract}, identity.Profile{ID: PrivadoRoleProfile, Kind: identity.PrivadoRole, VerifierID: verifier, Network: "polygon:mumbai", IdentityStateContract: PrivadoStateContract, AllowedCredentialIssuers: []string{issuer}, Context: PrivadoContextURL, ContextDigest: "sha256:" + hex.EncodeToString(sum[:]), Type: "BankRole", CircuitID: "credentialAtomicQuerySigV2", Predicates: []identity.Predicate{{ID: "reader", Field: "role", Operator: "eq", Value: "7"}}})
	s.Issuers[0].AllowedProfiles = append(s.Issuers[0].AllowedProfiles, PrivadoProfile, PrivadoRoleProfile)
	return s
}
func MultiBrokerSource() brokerpolicy.SourceV2 {
	s := BrokerSource()
	sum := sha256.Sum256(PrivadoContext)
	return brokerpolicy.SourceV2{APIVersion: brokerpolicy.MultiAPIVersion, Kind: s.Kind, IssuerID: s.IssuerID, AccessKeyID: s.AccessKeyID, WebOrigin: s.WebOrigin, CompletionURI: s.CompletionURI, AzureProfiles: s.AzureProfiles, PrivadoProfiles: []brokerpolicy.PrivadoBinding{{ProfileID: PrivadoProfile}, {ProfileID: PrivadoRoleProfile}}, PrivadoNetworks: []brokerpolicy.PrivadoNetwork{{Network: "polygon:mumbai", ChainID: "80001", StateContract: PrivadoStateContract, RPCURL: "https://state.test/rpc", AllowPrivate: false}}, PinnedDocuments: []brokerpolicy.PinnedDocumentRef{{URL: PrivadoContextURL, Path: "role-context.json", SHA256: "sha256:" + hex.EncodeToString(sum[:])}}, RenewalKeys: s.RenewalKeys, EncryptionKeys: s.EncryptionKeys}
}
func MultiSnapshot(t testing.TB, change func(*identity.SourceCatalog, *brokerpolicy.SourceV2)) *policybundle.CatalogSnapshot {
	t.Helper()
	ids, broker := MultiIdentitySource(t), MultiBrokerSource()
	if change != nil {
		change(&ids, &broker)
	}
	return snapshot(t, ids, broker, policybundle.BrokerMultiProfileID, map[string][]byte{"role-context.json": PrivadoContext})
}

// MultiSnapshotSources compiles explicitly supplied public test sources through
// the normal preparation and independently pinned loading path.
func MultiSnapshotSources(t testing.TB, ids identity.SourceCatalog, broker brokerpolicy.SourceV2, documents map[string][]byte) *policybundle.CatalogSnapshot {
	return snapshot(t, ids, broker, policybundle.BrokerMultiProfileID, documents)
}
