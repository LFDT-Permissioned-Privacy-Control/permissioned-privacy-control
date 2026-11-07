package identitybroker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"privacy-proxy/internal/brokerpolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/azure"
	"privacy-proxy/internal/policybundle"
)

type AccessSigningBinding struct {
	IssuerID, KeyID string
	PrivateKey      ed25519.PrivateKey
}
type Config struct {
	Snapshot                                  *policybundle.CatalogSnapshot
	Clock                                     identity.Clock
	Store                                     Store
	AzureProvider                             *azure.ProviderSet
	AccessSigningBinding                      AccessSigningBinding
	RenewalKeyBindings, EncryptionKeyBindings []SecretBinding
	ServiceBinding                            ServiceBinding
	ExpectedState                             ExpectedState
}
type Metadata struct {
	ManifestDigest, IdentityDigest, BrokerDigest, Namespace string
	Binding                                                 ServiceBinding
	RecoveryEpoch                                           string
}
type Service struct {
	snapshot *policybundle.CatalogSnapshot
	identity *identity.Catalog
	broker   *brokerpolicy.Catalog
	clock    identity.Clock
	store    Store
	provider *azure.ProviderSet
	scope    Scope
	metadata Metadata
	issuer   identity.Issuer
	keyID    string
	private  ed25519.PrivateKey
	mac, aes *keyring
	verifier *identity.Verifier
}

func New(c Config) (*Service, error) {
	if c.Snapshot == nil || c.Clock == nil || c.Store == nil || c.AzureProvider == nil || !c.ExpectedState.Valid() || len(c.AccessSigningBinding.PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	broker, ok := c.Snapshot.AuthBroker()
	if !ok {
		return nil, ErrInvalid
	}
	identities, ok := c.Snapshot.Identity()
	if !ok {
		return nil, ErrInvalid
	}
	source := broker.Source()
	issuer := broker.Issuer()
	meta := c.Snapshot.Metadata()
	if meta.Profile != policybundle.BrokerProfileID || meta.Environment != c.ServiceBinding.Environment || c.ServiceBinding.Origin != source.WebOrigin || c.AccessSigningBinding.IssuerID != issuer.ID || c.AccessSigningBinding.KeyID != source.AccessKeyID {
		return nil, ErrInvalid
	}
	providerMeta := c.AzureProvider.Metadata()
	if providerMeta.BrokerDigest != broker.Digest() || providerMeta.IdentityDigest != identities.Digest() {
		return nil, ErrInvalid
	}
	public := c.AccessSigningBinding.PrivateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(ed25519.NewKeyFromSeed(c.AccessSigningBinding.PrivateKey.Seed()), c.AccessSigningBinding.PrivateKey) {
		return nil, ErrInvalid
	}
	matched := false
	for _, key := range issuer.Keys {
		if key.Kid == source.AccessKeyID {
			raw, err := base64.RawURLEncoding.Strict().DecodeString(key.X)
			matched = err == nil && public.Equal(ed25519.PublicKey(raw))
		}
	}
	if !matched {
		return nil, ErrInvalid
	}
	mac, aes, err := newKeyrings(source, c.RenewalKeyBindings, c.EncryptionKeyBindings, c.AccessSigningBinding.PrivateKey)
	if err != nil {
		return nil, err
	}
	namespace, err := c.ServiceBinding.Namespace(issuer.Issuer)
	if err != nil {
		return nil, err
	}
	verifier, err := identity.NewVerifier(identities, c.Clock)
	if err != nil {
		return nil, ErrInvalid
	}
	return &Service{snapshot: c.Snapshot, identity: identities, broker: broker, clock: c.Clock, store: c.Store, provider: c.AzureProvider, scope: Scope{namespace, c.ExpectedState}, metadata: Metadata{string(meta.ManifestDigest), identities.Digest(), broker.Digest(), namespace.String(), c.ServiceBinding, c.ExpectedState.RecoveryEpoch}, issuer: issuer, keyID: source.AccessKeyID, private: append(ed25519.PrivateKey{}, c.AccessSigningBinding.PrivateKey...), mac: mac, aes: aes, verifier: verifier}, nil
}
func (s *Service) Metadata() Metadata { return s.metadata }
func brokerOperation(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 20*time.Second)
}
func (s *Service) now() (time.Time, error) {
	now := s.clock().UTC().Truncate(time.Microsecond)
	if now.Unix() < 0 || now.Unix() > 253402300799-int64(FamilyLifetime.Seconds()) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

type ResultMetadata struct {
	ActorID                                  string
	Kind                                     identity.Kind
	ExpiresAt                                time.Time
	ManifestDigest, ProfileID, ProfileDigest string
}
type AccessResult struct {
	service       *Service
	token         string
	metadata      ResultMetadata
	grantStart    time.Time
	familyExpires *time.Time
	sessionID     string
	valid         bool
}

func (r *AccessResult) Metadata() ResultMetadata {
	if r == nil {
		return ResultMetadata{}
	}
	return r.metadata
}
func (r *AccessResult) RequireDeliverable() error {
	if r == nil || !r.valid || r.service == nil {
		return ErrUnauthorized
	}
	now, err := r.service.now()
	if err != nil {
		return err
	}
	if now.Before(r.grantStart) || !now.Before(r.metadata.ExpiresAt) || r.familyExpires != nil && !now.Before(*r.familyExpires) {
		return ErrUnauthorized
	}
	digest, ok := r.service.identity.ProfileDigest(r.metadata.ProfileID)
	if !ok || digest != r.metadata.ProfileDigest || r.metadata.ManifestDigest != r.service.metadata.ManifestDigest {
		return ErrUnauthorized
	}
	if _, err := r.service.verifier.VerifyAccess(r.token); err != nil {
		return ErrUnauthorized
	}
	return nil
}
func (r *AccessResult) Credentials() (string, error) {
	if err := r.RequireDeliverable(); err != nil {
		return "", err
	}
	return r.token, nil
}

type CommittedLogin struct {
	access  *AccessResult
	refresh string
	valid   bool
}
type CommittedRenewal struct {
	access  *AccessResult
	refresh string
	valid   bool
}

type BrowserSession struct {
	ID, ActorID       string
	AbsoluteExpiresAt time.Time
}

func (r *AccessResult) sessionInfo() (BrowserSession, error) {
	if err := r.RequireDeliverable(); err != nil {
		return BrowserSession{}, err
	}
	if r.metadata.Kind != identity.Human || !ValidUUID(r.sessionID) || r.familyExpires == nil {
		return BrowserSession{}, ErrUnauthorized
	}
	now, err := r.service.now()
	if err != nil {
		return BrowserSession{}, err
	}
	// Refresh proofs encode integral Unix expiry; a rounded-down already-expired
	// handle must not be published in the family's final fractional second.
	if !now.Before(time.Unix(r.familyExpires.Unix(), 0)) {
		return BrowserSession{}, ErrUnauthorized
	}
	return BrowserSession{ID: r.sessionID, ActorID: r.metadata.ActorID, AbsoluteExpiresAt: *r.familyExpires}, nil
}
func (r *CommittedLogin) SessionInfo() (BrowserSession, error) {
	if err := r.RequireDeliverable(); err != nil {
		return BrowserSession{}, err
	}
	return r.access.sessionInfo()
}
func (r *CommittedRenewal) SessionInfo() (BrowserSession, error) {
	if err := r.RequireDeliverable(); err != nil {
		return BrowserSession{}, err
	}
	return r.access.sessionInfo()
}

func (r *CommittedLogin) Metadata() ResultMetadata {
	if r == nil {
		return ResultMetadata{}
	}
	return r.access.Metadata()
}
func (r *CommittedRenewal) Metadata() ResultMetadata {
	if r == nil {
		return ResultMetadata{}
	}
	return r.access.Metadata()
}
func (r *CommittedLogin) RequireDeliverable() error {
	if r == nil || !r.valid {
		return ErrUnauthorized
	}
	return r.access.RequireDeliverable()
}
func (r *CommittedRenewal) RequireDeliverable() error {
	if r == nil || !r.valid {
		return ErrUnauthorized
	}
	return r.access.RequireDeliverable()
}
func (r *CommittedLogin) Credentials() (string, string, error) {
	if err := r.RequireDeliverable(); err != nil {
		return "", "", err
	}
	return r.access.token, r.refresh, nil
}
func (r *CommittedRenewal) Credentials() (string, string, error) {
	if err := r.RequireDeliverable(); err != nil {
		return "", "", err
	}
	return r.access.token, r.refresh, nil
}
func (s *Service) buildAccess(evidence azure.Evidence, grantStart time.Time) (*AccessResult, error) {
	if !evidence.Valid() {
		return nil, ErrUnauthorized
	}
	source := evidence.Identity()
	profile, ok := s.broker.Profile(source.ProfileID)
	if !ok || profile.Digest != evidence.ProfileDigest() {
		return nil, ErrUnauthorized
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	if now.Before(grantStart) {
		return nil, ErrUnavailable
	}
	providerIssued, providerExpires, observed := evidence.Times()
	if observed > now.Unix()+30 || observed < grantStart.Unix() || providerExpires <= now.Unix() {
		return nil, ErrUnauthorized
	}
	claimsAsOf := grantStart.Unix()
	if source.Kind == identity.Service {
		claimsAsOf = min(providerIssued, now.Unix())
	}
	if claimsAsOf < 0 || claimsAsOf > math.MaxInt64-300 {
		return nil, ErrUnauthorized
	}
	expires := min(now.Unix()+300, claimsAsOf+300, providerExpires)
	if expires <= now.Unix() {
		return nil, ErrUnauthorized
	}
	actor, err := s.identity.SourceActorID(source)
	if err != nil {
		return nil, ErrUnauthorized
	}
	jti, err := randomToken()
	if err != nil {
		return nil, err
	}
	claims := identity.AccessClaims{Issuer: s.issuer.Issuer, Audience: s.issuer.Audience, Subject: actor, ID: jti, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: expires, PrincipalKind: source.Kind, SourceProfile: source.ProfileID, SourceProfileDigest: profile.Digest, IdentityAuthority: source.Authority, SourceSubject: source.Subject, SourceTenant: source.Tenant, SourceVerifiedAt: observed, ClaimsAsOf: claimsAsOf, SourceNotAfter: &providerExpires, Facts: evidence.Facts()}
	header, err := json.Marshal(identity.AccessHeader{Typ: "ops-access+jwt", Alg: "EdDSA", Kid: s.keyID})
	if err != nil {
		return nil, ErrUnavailable
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, ErrUnavailable
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature, err := jwt.SigningMethodEdDSA.Sign(encoded, s.private)
	if err != nil {
		return nil, ErrUnavailable
	}
	token := encoded + "." + base64.RawURLEncoding.EncodeToString(signature)
	principal, err := s.verifier.VerifyAccess(token)
	if err != nil || principal.ActorID() != actor || principal.Kind() != source.Kind {
		return nil, ErrUnauthorized
	}
	return &AccessResult{service: s, token: token, metadata: ResultMetadata{actor, source.Kind, time.Unix(expires, 0).UTC(), s.metadata.ManifestDigest, source.ProfileID, profile.Digest}, grantStart: grantStart, valid: true}, nil
}
func (s *Service) ExchangeAzureService(ctx context.Context, profileID, rawToken string) (*AccessResult, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	at, err := s.now()
	if err != nil {
		return nil, err
	}
	evidence, err := s.provider.VerifyService(ctx, profileID, rawToken)
	if err != nil {
		return nil, providerError(err)
	}
	result, err := s.buildAccess(evidence, at)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if err := result.RequireDeliverable(); err != nil {
		return nil, err
	}
	return result, nil
}
func providerError(err error) error {
	switch err {
	case azure.ErrRelogin:
		return ErrRelogin
	case azure.ErrEvidence, azure.ErrInvalid:
		return ErrUnauthorized
	default:
		return ErrUnavailable
	}
}
