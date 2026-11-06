// Package identity verifies local OPS assertions against immutable approved
// public trust and fact mappings. It contains no issuer, provider or session
// implementation and makes no claim of production authentication readiness.
package identity

const (
	APIVersion      = "ops.identity-catalog/v1alpha1"
	CatalogKind     = "IdentityCatalog"
	AzureHuman      = "azure-human/v1"
	AzureService    = "azure-service/v1"
	PrivadoIdentity = "privado-identity/v1"
	PrivadoRole     = "privado-role-query/v1"
)

type Kind string

const (
	Human   Kind = "human"
	Service Kind = "service"
)

type SourceCatalog struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Issuers    []Issuer  `json:"issuers"`
	Profiles   []Profile `json:"profiles"`
	Mappings   []Mapping `json:"mappings"`
}

type Issuer struct {
	ID              string      `json:"id"`
	Issuer          string      `json:"issuer"`
	Audience        string      `json:"audience"`
	Keys            []PublicKey `json:"keys"`
	AllowedProfiles []string    `json:"allowedProfiles"`
}
type PublicKey struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// Profile is a flat discriminated source object. Field order is part of the
// canonical profile encoding. Decode/Compile require the exact variant fields;
// omitempty never permits mixing fields from different source kinds.
type Profile struct {
	ID                       string      `json:"id"`
	Kind                     string      `json:"kind"`
	TenantID                 string      `json:"tenantId,omitempty"`
	Issuer                   string      `json:"issuer,omitempty"`
	APIAudience              string      `json:"apiAudience,omitempty"`
	ClientID                 string      `json:"clientId,omitempty"`
	DelegatedScope           string      `json:"delegatedScope,omitempty"`
	AllowedClientIDs         []string    `json:"allowedClientIds,omitempty"`
	FactSource               string      `json:"factSource,omitempty"`
	VerifierID               string      `json:"verifierId,omitempty"`
	Network                  string      `json:"network,omitempty"`
	IdentityStateContract    string      `json:"identityStateContract,omitempty"`
	AllowedCredentialIssuers []string    `json:"allowedCredentialIssuers,omitempty"`
	ContextDigest            string      `json:"contextDigest,omitempty"`
	Context                  string      `json:"context,omitempty"`
	Type                     string      `json:"type,omitempty"`
	CircuitID                string      `json:"circuitId,omitempty"`
	Predicates               []Predicate `json:"predicates,omitempty"`
}
type Predicate struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}
type Fact struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type Mapping struct {
	ID             string   `json:"id"`
	ProfileID      string   `json:"profileId"`
	OrganizationID string   `json:"organizationId"`
	PrincipalKind  Kind     `json:"principalKind"`
	Fact           Fact     `json:"fact"`
	GroupIDs       []string `json:"groupIds"`
}

// GroupIndex is consulted only during Compile. Its trusted stable view is
// snapshotted and discarded; no request principal retains this callback.
type GroupIndex interface {
	HasGroup(orgID, groupID string) bool
}
