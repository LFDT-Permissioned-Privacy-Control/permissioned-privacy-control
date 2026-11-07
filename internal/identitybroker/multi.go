package identitybroker

import (
	"crypto/ed25519"
	"net/http"
	"sync"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/azure"
	"privacy-proxy/internal/identitybroker/privado"
	"privacy-proxy/internal/policybundle"
)

type RPCSecretBinding struct{ FromEnv, Value string }

const MaxMultiHTTPInFlight = 8

type MultiConfig struct {
	Snapshot                                  *policybundle.CatalogSnapshot
	Clock                                     identity.Clock
	Store                                     MultiStore
	PublicProofStore                          PrivadoProofStore
	AzureProvider                             *azure.ProviderSet
	AccessSigningBinding                      AccessSigningBinding
	RenewalKeyBindings, EncryptionKeyBindings []SecretBinding
	ServiceBinding                            ServiceBinding
	ExpectedState                             ExpectedState
	PrivadoRPCSecretBindings                  []RPCSecretBinding
	PrivadoTransport                          http.RoundTripper
}

// NewMulti constructs the verifier itself from the one approved snapshot. A
// provider implementation, query, document bytes or network override cannot be
// injected as an alternate identity authority.
func NewMulti(c MultiConfig) (*Service, error) {
	if c.Snapshot == nil || c.Store == nil || c.PublicProofStore == nil || c.Clock == nil || len(c.AccessSigningBinding.PrivateKey) != ed25519.PrivateKeySize || c.Snapshot.Metadata().Profile != policybundle.BrokerMultiProfileID {
		return nil, ErrInvalid
	}
	auth, ok := c.Snapshot.AuthBroker()
	if !ok {
		return nil, ErrInvalid
	}
	source, ok := auth.MultiSource()
	if !ok {
		return nil, ErrInvalid
	}
	identities, ok := c.Snapshot.Identity()
	if !ok {
		return nil, ErrInvalid
	}
	s, e := newService(Config{Snapshot: c.Snapshot, Clock: c.Clock, Store: c.Store, AzureProvider: c.AzureProvider, AccessSigningBinding: c.AccessSigningBinding, RenewalKeyBindings: c.RenewalKeyBindings, EncryptionKeyBindings: c.EncryptionKeyBindings, ServiceBinding: c.ServiceBinding, ExpectedState: c.ExpectedState}, true)
	if e != nil {
		return nil, e
	}
	if c.Store.Binding() != (PrivadoStoreBinding{Scope: s.scope, SchemaVersion: 2, Role: "private-app"}) || c.PublicProofStore.Binding() != (PrivadoStoreBinding{Scope: s.scope, SchemaVersion: 2, Role: "public-proof"}) {
		return nil, ErrInvalid
	}
	secrets := map[string]string{}
	for _, b := range c.PrivadoRPCSecretBindings {
		if _, exists := secrets[b.FromEnv]; exists || b.Value == "" {
			return nil, ErrInvalid
		}
		secrets[b.FromEnv] = b.Value
	}
	needed := map[string]bool{}
	o := privado.Options{Catalog: identities, Clock: c.Clock, Transport: c.PrivadoTransport}
	for _, b := range source.PrivadoProfiles {
		o.ProfileIDs = append(o.ProfileIDs, b.ProfileID)
	}
	for _, n := range source.PrivadoNetworks {
		binding := privado.NetworkBinding{Network: n.Network, ChainID: n.ChainID, StateContract: n.StateContract, URL: n.RPCURL, AllowPrivate: n.AllowPrivate}
		if n.Credential != nil {
			value, exists := secrets[n.Credential.FromEnv]
			if !exists {
				return nil, ErrInvalid
			}
			needed[n.Credential.FromEnv] = true
			binding.Credential = &privado.CredentialBinding{RefID: n.Credential.FromEnv, Header: n.Credential.Header, Value: value}
		}
		o.Networks = append(o.Networks, binding)
	}
	if len(needed) != len(secrets) {
		return nil, ErrInvalid
	}
	for _, d := range auth.PinnedDocuments() {
		o.Documents = append(o.Documents, privado.PinnedDocument{URL: d.URL, RawBytes: d.RawBytes})
	}
	p, e := privado.New(o)
	if e != nil {
		return nil, ErrInvalid
	}
	if len(source.WebOrigin)+len(privadoProofPath)+36 > 2048 {
		p.Close()
		return nil, ErrInvalid
	}
	s.privado = p
	s.app = c.Store
	s.proofStore = c.PublicProofStore
	s.httpSlots = make(chan struct{}, MaxMultiHTTPInFlight)
	return s, nil
}

// TryAdmitHTTP bounds the whole owned broker instance across all its NewMulti
// handlers. It does not queue. Fixed public OPTIONS does not call this method.
func (s *Service) TryAdmitHTTP() (func(), bool) {
	if !s.IsMulti() || s.httpSlots == nil {
		return nil, false
	}
	select {
	case s.httpSlots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.httpSlots }) }, true
	default:
		return nil, false
	}
}
func (s *Service) Close() {
	if s != nil && s.privado != nil {
		s.privado.Close()
	}
}
func (s *Service) IsMulti() bool { return s != nil && s.multi && s.privado != nil }
