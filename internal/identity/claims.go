package identity

// AccessHeader and AccessClaims share the exact Core wire DTOs with the trusted
// issuer. Constructing these values grants no identity or authorization; signed
// output must still pass VerifyAccess against the selected catalog.
type AccessHeader = accessHeader
type AccessClaims = accessClaims

type accessHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type accessClaims struct {
	Issuer              string  `json:"iss"`
	Audience            string  `json:"aud"`
	Subject             string  `json:"sub"`
	ID                  string  `json:"jti"`
	IssuedAt            int64   `json:"iat"`
	NotBefore           int64   `json:"nbf"`
	Expires             int64   `json:"exp"`
	PrincipalKind       Kind    `json:"principal_kind"`
	SourceProfile       string  `json:"source_profile"`
	SourceProfileDigest string  `json:"source_profile_digest"`
	IdentityAuthority   string  `json:"identity_authority"`
	SourceSubject       string  `json:"source_subject"`
	SourceTenant        *string `json:"source_tenant,omitempty" optional:"true"`
	SourceVerifiedAt    int64   `json:"source_verified_at"`
	ClaimsAsOf          int64   `json:"claims_as_of"`
	SourceNotAfter      *int64  `json:"source_not_after,omitempty" optional:"true"`
	Facts               []Fact  `json:"facts"`
}
