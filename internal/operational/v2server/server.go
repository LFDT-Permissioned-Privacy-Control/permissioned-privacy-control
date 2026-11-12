package v2server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identitybroker/azure"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/identitysql"
	"privacy-proxy/internal/operational/identityweb"
	"privacy-proxy/internal/operational/ssohttp"
	"privacy-proxy/internal/operational/ssosql"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policyprofiles"
	"privacy-proxy/internal/selfhttp"
	"privacy-proxy/internal/ssopolicy"
	m "privacy-proxy/internal/ssotransaction"
	"privacy-proxy/internal/wallethttp"
	"privacy-proxy/internal/walletops"
)

// Server is deliberately SQL-linked. Its Core snapshot is a single immutable
// pointer; the broker has its separately approved, differently profiled bundle.
type Server struct {
	core        *policybundle.CatalogSnapshot
	handler     *http.ServeMux
	config      Config
	certificate tls.Certificate
	close       []func()
	once        sync.Once
	data        *dataPlane
	dataReady   bool // set only by the actual shared RPC/Explorer/protected assembly
}

func (s *Server) Close() {
	if s != nil {
		s.once.Do(func() {
			for i := len(s.close) - 1; i >= 0; i-- {
				s.close[i]()
			}
		})
	}
}
func (s *Server) Handler() http.Handler { return s.handler }
func load(ctx context.Context, s Selection, profile string) (*policybundle.CatalogSnapshot, error) {
	if _, e := digest(s.ManifestDigest); e != nil {
		return nil, e
	}
	options, _, e := policyprofiles.Options(profile)
	if profile == policybundle.RuntimeCreationObservedProfileID {
		options, _, e = policyprofiles.DeliveryOptions(profile)
	}
	if e != nil {
		return nil, e
	}
	return policybundle.LoadDirectory(ctx, policybundle.Selection{Directory: s.Directory, ExpectedManifestDigest: policybundle.Digest(s.ManifestDigest), ExpectedEnvironment: s.Environment, ExpectedChainID: s.ChainID}, options)
}

func Open(parent context.Context, c Config) (*Server, error) {
	if parent == nil {
		return nil, ErrInvalid
	}
	s := &Server{config: c, handler: http.NewServeMux()}
	fail := func(stage string) (*Server, error) { s.Close(); return nil, fmt.Errorf("%s startup failed", stage) }
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	core, e := load(ctx, c.Core, policybundle.RuntimeCreationObservedProfileID)
	if e != nil {
		return fail("Core bundle")
	}
	s.core = core
	if c.ExplorerOrganizationID != "" && !(references{core}).Organization(c.ExplorerOrganizationID) {
		return fail("Explorer organization")
	}
	brokerSnapshot, e := load(ctx, c.BrokerSelection, policybundle.BrokerMultiProfileID)
	if e != nil {
		return fail("broker bundle")
	}
	coreIDs, ok := core.Identity()
	if !ok {
		return fail("Core identity")
	}
	brokerIDs, ok := brokerSnapshot.Identity()
	if !ok || coreIDs.Digest() != brokerIDs.Digest() || core.Metadata().Environment != brokerSnapshot.Metadata().Environment || core.Metadata().ChainID != brokerSnapshot.Metadata().ChainID {
		return fail("identity binding")
	}
	cert, e := readFile(c.TLSCertificateFile, 1<<20)
	if e != nil {
		return fail("TLS certificate")
	}
	key, e := readFile(c.TLSPrivateKeyFile, 64<<10)
	if e != nil {
		return fail("TLS key")
	}
	s.certificate, e = tls.X509KeyPair(cert, key)
	if e != nil {
		return fail("TLS pair")
	}
	auth, ok := brokerSnapshot.AuthBroker()
	if !ok {
		return fail("broker catalog")
	}
	source, ok := auth.MultiSource()
	if !ok {
		return fail("broker profile")
	}
	binding := b.ServiceBinding{Environment: brokerSnapshot.Metadata().Environment, DeploymentID: c.Broker.DeploymentID, Origin: source.WebOrigin}
	ns, e := binding.Namespace(auth.Issuer().Issuer)
	if e != nil {
		return fail("broker namespace")
	}
	scope := b.Scope{Namespace: ns, State: b.ExpectedState{RecoveryEpoch: c.Broker.RecoveryEpoch}}
	dsn, e := secret(c.Broker.AppDSNEnv)
	if e != nil {
		return fail("broker DSN")
	}
	app, e := identitysql.OpenPrivateV2(ctx, dsn, scope, time.Now)
	if e != nil {
		return fail("broker store")
	}
	s.close = append(s.close, app.Close)
	dsn, e = secret(c.Broker.ProofDSNEnv)
	if e != nil {
		return fail("proof DSN")
	}
	proof, e := identitysql.OpenProofV2(ctx, dsn, scope, time.Now)
	if e != nil {
		return fail("proof store")
	}
	s.close = append(s.close, proof.Close)
	azureSecrets := map[string]string{}
	for _, profile := range source.AzureProfiles {
		if profile.ClientSecret != nil {
			value, e := secret(profile.ClientSecret.FromEnv)
			if e != nil {
				return fail("Azure secret")
			}
			azureSecrets[profile.ClientSecret.FromEnv] = value
		}
	}
	provider, e := azure.New(ctx, azure.Config{Catalog: auth, Clock: time.Now, ClientSecrets: azureSecrets})
	if e != nil {
		return fail("Azure provider")
	}
	s.close = append(s.close, provider.Close)
	private, e := binarySecret(c.Broker.SigningPrivateKeyEnv, ed25519.PrivateKeySize)
	if e != nil {
		return fail("access signing key")
	}
	renewal, e := keyBindings(source.RenewalKeys)
	if e != nil {
		return fail("renewal keys")
	}
	encryption, e := keyBindings(source.EncryptionKeys)
	if e != nil {
		return fail("broker encryption keys")
	}
	var rpcSecrets []b.RPCSecretBinding
	rpcSeen := map[string]bool{}
	for _, network := range source.PrivadoNetworks {
		if network.Credential != nil && !rpcSeen[network.Credential.FromEnv] {
			value, e := secret(network.Credential.FromEnv)
			if e != nil {
				return fail("Privado RPC secret")
			}
			rpcSecrets = append(rpcSecrets, b.RPCSecretBinding{FromEnv: network.Credential.FromEnv, Value: value})
			rpcSeen[network.Credential.FromEnv] = true
		}
	}
	broker, e := b.NewMulti(b.MultiConfig{Snapshot: brokerSnapshot, Clock: time.Now, Store: app, PublicProofStore: proof, AzureProvider: provider, AccessSigningBinding: b.AccessSigningBinding{IssuerID: source.IssuerID, KeyID: source.AccessKeyID, PrivateKey: ed25519.PrivateKey(private)}, RenewalKeyBindings: renewal, EncryptionKeyBindings: encryption, ServiceBinding: binding, ExpectedState: scope.State, PrivadoRPCSecretBindings: rpcSecrets})
	if e != nil {
		return fail("broker")
	}
	s.close = append(s.close, broker.Close)
	browser, e := identityhttp.NewMulti(identityhttp.Config{Snapshot: brokerSnapshot, Service: broker, Clock: time.Now})
	if e != nil {
		return fail("broker HTTP")
	}
	browser.Register(s.handler)
	self, e := selfhttp.New(selfhttp.Config{Snapshot: core, Origin: source.WebOrigin, Clock: time.Now})
	if e != nil {
		return fail("self HTTP")
	}
	self.Register(s.handler)
	web, e := identityweb.New(identityweb.Config{Snapshot: brokerSnapshot, Files: os.DirFS(c.WebDirectory)})
	if e != nil {
		return fail("browser assets")
	}
	web.Register(s.handler)
	coverage, e := walletsql.Digest(c.Wallet.CoverageDigest)
	if e != nil {
		return fail("wallet coverage")
	}
	walletBinding := walletops.ServiceBinding{ServiceOrigin: c.Wallet.ServiceOrigin, Environment: core.Metadata().Environment, ChainID: core.Metadata().ChainID, GenesisHash: c.Wallet.GenesisHash, DeploymentID: c.Wallet.DeploymentID}
	walletState := walletops.ExpectedState{Generation: c.Wallet.Generation, Coverage: coverage}
	dsn, e = secret(c.Wallet.AppDSNEnv)
	if e != nil {
		return fail("wallet DSN")
	}
	walletStore, e := walletsql.Open(ctx, dsn)
	if e != nil {
		return fail("wallet store")
	}
	s.close = append(s.close, walletStore.Close)
	wallet, e := walletops.New(walletops.Config{Snapshot: core, Clock: time.Now, Binding: walletBinding, State: walletState, Store: walletStore})
	if e != nil {
		return fail("wallet")
	}
	walletHTTP, e := wallethttp.New(wallet)
	if e != nil {
		return fail("wallet HTTP")
	}
	walletHTTP.RegisterLinks(s.handler)
	clientBytes, e := readPinned(c.SSO.Clients, 256<<10)
	if e != nil {
		return fail("SSO clients")
	}
	clients, e := ssopolicy.Compile(clientBytes, coreIDs, references{core})
	if e != nil {
		return fail("SSO clients catalog")
	}
	runtimeBytes, e := readPinned(c.SSO.Runtime, 64<<10)
	if e != nil {
		return fail("SSO runtime")
	}
	runtimeDigest, e := digest(c.SSO.Runtime.Digest)
	if e != nil {
		return fail("SSO runtime digest")
	}
	var runtime ssohttp.RuntimeSource
	if jsonDecodeRuntime(runtimeBytes, &runtime) != nil {
		return fail("SSO runtime source")
	}
	contextKey, e := binarySecret(runtime.ContextKey.FromEnv, 32)
	if e != nil {
		return fail("SSO context key")
	}
	grantKey, e := binarySecret(runtime.GrantKey.FromEnv, 32)
	if e != nil {
		return fail("SSO grant key")
	}
	clientSecrets := []ssohttp.SecretBinding{}
	seen := map[string]bool{}
	for _, client := range clients.Clients() {
		ref := client.Source().Secret.FromEnv
		if !seen[ref] {
			value, e := secret(ref)
			if e != nil {
				return fail("SSO client secret")
			}
			seen[ref] = true
			clientSecrets = append(clientSecrets, ssohttp.SecretBinding{FromEnv: ref, Value: []byte(value)})
		}
	}
	ssoNS, e := m.NamespaceFor(m.Digest(ns), source.WebOrigin)
	if e != nil {
		return fail("SSO namespace")
	}
	ssoScope := m.Scope{Namespace: ssoNS, Epoch: c.SSO.RecoveryEpoch, BrokerNamespace: m.Digest(ns), BrokerRecoveryEpoch: scope.State.RecoveryEpoch}
	dsn, e = secret(c.SSO.AppDSNEnv)
	if e != nil {
		return fail("SSO DSN")
	}
	ssoStore, e := ssosql.OpenApp(ctx, ssosql.Config{DSN: dsn, Expected: ssoScope, Clock: time.Now})
	if e != nil {
		return fail("SSO store")
	}
	s.close = append(s.close, ssoStore.Close)
	sso, e := ssohttp.New(ssohttp.Config{CoreSnapshot: core, BrokerSnapshot: brokerSnapshot, Broker: broker, Store: ssoStore, Clients: clients, RuntimeSourceJSON: runtimeBytes, ExpectedSourceSHA256: runtimeDigest, EncryptionBindings: []ssohttp.SecretBinding{{FromEnv: runtime.ContextKey.FromEnv, Value: contextKey}, {FromEnv: runtime.GrantKey.FromEnv, Value: grantKey}}, ClientSecretBindings: clientSecrets, Clock: time.Now, SecurityLog: slog.Default()})
	if e != nil {
		return fail("SSO HTTP")
	}
	sso.Register(s.handler)
	s.data, e = s.buildData(ctx, walletBinding, walletState)
	if e != nil {
		return fail("data plane")
	}
	if e = s.mountRPC(s.data); e != nil {
		return fail("RPC HTTP")
	}
	if e = s.mountProtected(ctx, s.data, walletBinding, walletState); e != nil {
		return fail("protected data")
	}
	s.dataReady = true
	s.handler.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
	return s, nil
}

type references struct{ snapshot *policybundle.CatalogSnapshot }

func (r references) Organization(id string) bool {
	for _, org := range r.snapshot.Organizations() {
		if org.ID == id {
			return true
		}
	}
	return false
}
func (r references) Group(org, id string) bool { _, ok := r.snapshot.Group(org, id); return ok }

func (s *Server) Serve(ctx context.Context) error {
	// The approved delivery profile advertises actual data consumers. Do not
	// start a partial identity-only listener under that profile while they are
	// still being composed; no placeholder route stands in for those services.
	if !s.dataReady {
		return errors.New("Core delivery consumers are not configured")
	}
	if ctx == nil || s.data == nil || s.data.recorder == nil || s.data.recorder.CheckHealth() != nil {
		return ErrInvalid
	}
	// The sealer and feed outlive the HTTP drain. Request cancellation is not a
	// reason to close SQL/Pebble underneath a still-owned completion operation.
	workers, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	if s.data.feed != nil {
		if e := s.data.feed.Start(workers); e != nil {
			return e
		}
	}
	go func() {
		if e := s.data.recorder.Run(workers); e != nil {
			slog.Error("activity recorder stopped")
		}
	}()
	server := &http.Server{Addr: s.config.Listen, Handler: s.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{s.certificate}}}
	done := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdown); err != nil {
				_ = server.Close()
			}
		case <-done:
		}
	}()
	err := server.ListenAndServeTLS("", "")
	close(done)
	<-shutdownDone
	s.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
