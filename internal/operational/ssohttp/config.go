// Package ssohttp composes the actual broker, Core verifier and operational SSO
// store. It returns original short-lived access tokens only to trusted apps.
package ssohttp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"time"

	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/operational/ssosql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/ssopolicy"
	m "privacy-proxy/internal/ssotransaction"
	"privacy-proxy/internal/strictjson"
)

type KeyRef struct {
	ID      string `json:"id"`
	FromEnv string `json:"fromEnv"`
}
type RuntimeSource struct {
	APIVersion           string `json:"apiVersion"`
	Kind                 string `json:"kind"`
	CoreManifestDigest   string `json:"coreManifestDigest"`
	BrokerManifestDigest string `json:"brokerManifestDigest"`
	ClientCatalogDigest  string `json:"clientCatalogDigest"`
	ContextKey           KeyRef `json:"contextKey"`
	GrantKey             KeyRef `json:"grantKey"`
}
type SecretBinding = b.SecretBinding
type Config struct {
	CoreSnapshot, BrokerSnapshot             *policybundle.CatalogSnapshot
	Broker                                   *b.Service
	Store                                    *ssosql.Store
	Clients                                  *ssopolicy.Catalog
	RuntimeSourceJSON                        []byte
	ExpectedSourceSHA256                     [32]byte
	EncryptionBindings, ClientSecretBindings []SecretBinding
	Clock                                    identity.Clock
	SecurityLog                              *slog.Logger
}
type Handler struct {
	broker                        *b.Service
	store                         *ssosql.Store
	clients                       *ssopolicy.Catalog
	factory                       *runtimepolicy.Factory
	clock                         identity.Clock
	log                           *slog.Logger
	origin, host                  string
	runtime                       RuntimeSource
	runtimeDigest                 m.Digest
	identityDigest, clientsDigest m.Digest
	scope                         m.Scope
	contextCipher, grantCipher    cipher.AEAD
	secrets                       map[string][32]byte
	secretLengths                 map[string]int
}

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func closed(raw []byte, out any, max int) error {
	if len(raw) < 1 || len(raw) > max {
		return b.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := strictjson.ReadValue(d, 0, 8)
	if e != nil {
		return b.ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return b.ErrInvalid
	}
	if strictjson.ExactDecode(v, out) != nil {
		return b.ErrInvalid
	}
	return nil
}
func parseDigest(raw string) (m.Digest, error) {
	d, e := b.ParseDigest(raw)
	if e != nil || d == (b.Digest{}) {
		return m.Digest{}, b.ErrInvalid
	}
	return m.Digest(d), nil
}
func makeCipher(raw []byte) (cipher.AEAD, error) {
	block, e := aes.NewCipher(raw)
	if e != nil {
		return nil, b.ErrInvalid
	}
	return cipher.NewGCM(block)
}
func New(c Config) (*Handler, error) {
	if c.CoreSnapshot == nil || c.BrokerSnapshot == nil || c.Broker == nil || !c.Broker.IsMulti() || c.Store == nil || c.Clients == nil || c.Clock == nil || c.ExpectedSourceSHA256 == [32]byte{} || sha256.Sum256(c.RuntimeSourceJSON) != c.ExpectedSourceSHA256 {
		return nil, b.ErrInvalid
	}
	var r RuntimeSource
	if closed(c.RuntimeSourceJSON, &r, 64<<10) != nil || r.APIVersion != "ops.sso.runtime/v1" || r.Kind != "SSORuntime" || !m.ValidName(r.ContextKey.ID) || !m.ValidName(r.GrantKey.ID) || !envName.MatchString(r.ContextKey.FromEnv) || !envName.MatchString(r.GrantKey.FromEnv) || r.ContextKey.ID == r.GrantKey.ID || r.ContextKey.FromEnv == r.GrantKey.FromEnv {
		return nil, b.ErrInvalid
	}
	ids, ok := c.CoreSnapshot.Identity()
	if !ok {
		return nil, b.ErrInvalid
	}
	auth, ok := c.BrokerSnapshot.AuthBroker()
	if !ok {
		return nil, b.ErrInvalid
	}
	bi, ok := c.BrokerSnapshot.Identity()
	if !ok {
		return nil, b.ErrInvalid
	}
	core, meta, actual := c.CoreSnapshot.Metadata(), c.BrokerSnapshot.Metadata(), c.Broker.Metadata()
	source := auth.CommonSettings()
	if meta.Profile != policybundle.BrokerMultiProfileID || string(meta.ManifestDigest) != actual.ManifestDigest || bi.Digest() != actual.IdentityDigest || auth.Digest() != actual.BrokerDigest || meta.Environment != actual.Binding.Environment || actual.Binding.Origin != source.WebOrigin || core.Environment != meta.Environment || core.ChainID != meta.ChainID || ids.Digest() != bi.Digest() || ids.Digest() != c.Clients.IdentityDigest() || r.CoreManifestDigest != string(core.ManifestDigest) || r.BrokerManifestDigest != string(meta.ManifestDigest) || r.ClientCatalogDigest != c.Clients.Digest() {
		return nil, b.ErrInvalid
	}
	for _, d := range []string{r.CoreManifestDigest, r.BrokerManifestDigest, r.ClientCatalogDigest} {
		if _, e := parseDigest(d); e != nil {
			return nil, e
		}
	}
	brokerNS, e := parseDigest(actual.Namespace)
	if e != nil {
		return nil, e
	}
	expected, e := m.NamespaceFor(brokerNS, source.WebOrigin)
	if e != nil {
		return nil, b.ErrInvalid
	}
	storeMetadata, e := c.Store.AppMetadata()
	if e != nil {
		return nil, b.ErrInvalid
	}
	scope := storeMetadata.Scope
	if !scope.Valid() || scope.Namespace != expected || scope.BrokerNamespace != brokerNS || scope.BrokerRecoveryEpoch != actual.RecoveryEpoch {
		return nil, b.ErrInvalid
	}
	keys := map[string][]byte{}
	if len(c.EncryptionBindings) != 2 {
		return nil, b.ErrInvalid
	}
	for _, key := range c.EncryptionBindings {
		if _, found := keys[key.FromEnv]; found {
			return nil, b.ErrInvalid
		}
		keys[key.FromEnv] = bytes.Clone(key.Value)
	}
	ck, cok := keys[r.ContextKey.FromEnv]
	gk, gok := keys[r.GrantKey.FromEnv]
	if !cok || !gok {
		return nil, b.ErrInvalid
	}
	clients := c.Clients.Clients()
	if len(c.ClientSecretBindings) != len(clients) {
		return nil, b.ErrInvalid
	}
	supplied := map[string][]byte{}
	for _, secret := range c.ClientSecretBindings {
		if _, found := supplied[secret.FromEnv]; found || !envName.MatchString(secret.FromEnv) {
			return nil, b.ErrInvalid
		}
		supplied[secret.FromEnv] = bytes.Clone(secret.Value)
	}
	secretHashes := map[string][32]byte{}
	secretLengths := map[string]int{}
	selectedRefs := map[string]bool{}
	for _, client := range clients {
		ref := client.Source().Secret.FromEnv
		v, found := supplied[ref]
		if !found || selectedRefs[ref] {
			return nil, b.ErrInvalid
		}
		selectedRefs[ref] = true
		secretHashes[client.Source().ID] = sha256.Sum256(v)
		secretLengths[client.Source().ID] = len(v)
	}
	if e = c.Broker.CheckHandoffSecrets(SecretBinding{FromEnv: r.ContextKey.FromEnv, Value: ck}, SecretBinding{FromEnv: r.GrantKey.FromEnv, Value: gk}, c.ClientSecretBindings); e != nil {
		return nil, e
	}
	factory, e := runtimepolicy.NewFactory(c.CoreSnapshot, c.Clock)
	if e != nil {
		return nil, b.ErrInvalid
	}
	cc, e := makeCipher(ck)
	if e != nil {
		return nil, e
	}
	gc, e := makeCipher(gk)
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(source.WebOrigin)
	if e != nil {
		return nil, b.ErrInvalid
	}
	identityDigest, e := parseDigest(ids.Digest())
	if e != nil {
		return nil, e
	}
	clientDigest, e := parseDigest(c.Clients.Digest())
	if e != nil {
		return nil, e
	}
	logger := c.SecurityLog
	if logger == nil {
		logger = slog.Default()
	}
	h := &Handler{broker: c.Broker, store: c.Store, clients: c.Clients, factory: factory, clock: c.Clock, log: logger, origin: source.WebOrigin, host: u.Host, runtime: r, runtimeDigest: m.Digest(c.ExpectedSourceSHA256), identityDigest: identityDigest, clientsDigest: clientDigest, scope: scope, contextCipher: cc, grantCipher: gc, secrets: secretHashes, secretLengths: secretLengths}
	if _, e = h.now(); e != nil {
		return nil, e
	}
	return h, nil
}
func (h *Handler) now() (time.Time, error) {
	t := h.clock().UTC()
	if t.Before(time.Unix(0, 0)) || t.After(time.Unix(253402300799, 999999999)) {
		return time.Time{}, b.ErrUnavailable
	}
	return t, nil
}
func (h *Handler) eligible(client ssopolicy.Client, v *runtimepolicy.View) error {
	if v == nil || v.Kind() != identity.Human || v.RequireLive() != nil {
		return b.ErrUnauthorized
	}
	s := client.Source()
	trust := map[string]bool{}
	for _, id := range s.TrustedOrganizationIDs {
		trust[id] = true
	}
	for _, id := range v.OrgIDs() {
		if !trust[id] {
			return b.ErrUnauthorized
		}
	}
	profile, _ := v.SourceProfile()
	allowedProfile := false
	for _, id := range s.AllowedProfiles {
		allowedProfile = allowedProfile || id == profile
	}
	if !allowedProfile {
		return b.ErrUnauthorized
	}
	if s.Eligibility == ssopolicy.ProfileEligibility {
		return nil
	}
	for _, g := range s.EligibleGroups {
		if org, ok := v.Org(g.OrganizationID); ok && org.HasGroup(g.GroupID) {
			return nil
		}
	}
	return b.ErrUnauthorized
}
