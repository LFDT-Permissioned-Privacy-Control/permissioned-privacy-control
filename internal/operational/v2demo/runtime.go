package v2demo

import (
	"context"
	"fmt"
	"os"
	"strings"

	"privacy-proxy/internal/operational/ssohttp"
	vs "privacy-proxy/internal/operational/v2server"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpchistorypolicy"
	"privacy-proxy/internal/rpcmetadatapolicy"
	"privacy-proxy/internal/rpcstatepolicy"
	"privacy-proxy/internal/ssopolicy"
)

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
func runtimeFiles(ctx context.Context, s State, core, broker *policybundle.CatalogSnapshot, cfg *vs.Config) error {
	ids, _ := core.Identity()
	source := ids.Source()
	profiles := []string{}
	appProfiles := []map[string]string{}
	for _, p := range source.Profiles {
		profiles = append(profiles, p.ID)
		d, _ := ids.ProfileDigest(p.ID)
		appProfiles = append(appProfiles, map[string]string{"id": p.ID, "digest": d})
	}
	clientsSource := ssopolicy.Source{APIVersion: ssopolicy.APIVersion, Kind: ssopolicy.Kind, Clients: []ssopolicy.ClientSource{{ID: "explorer", DisplayName: "Local V2 Explorer", Authentication: "client_secret_basic", Secret: ssopolicy.SecretRef{FromEnv: "DEMO_EXPLORER_SECRET"}, TrustMode: "first-party-full-core-bearer", TrustedOrganizationIDs: []string{Organization}, EligibleGroups: []ssopolicy.GroupRef{}, Eligibility: ssopolicy.ProfileEligibility, AllowedProfiles: profiles, RedirectURIs: []string{s.ExplorerOrigin() + "/api/auth/callback"}}}}
	cf, e := writeJSON(s.file("ops/clients.json"), clientsSource)
	if e != nil {
		return e
	}
	// Client catalog identity binds the exact published bytes, including their
	// formatting. Derive the runtime pin from the file the server will load.
	raw, e := os.ReadFile(cf.Path)
	if e != nil {
		return e
	}
	clients, e := ssopolicy.Compile(raw, ids, references{core})
	if e != nil {
		return e
	}
	rf, e := writeJSON(s.file("ops/sso-runtime.json"), ssohttp.RuntimeSource{APIVersion: "ops.sso.runtime/v1", Kind: "SSORuntime", CoreManifestDigest: string(core.Metadata().ManifestDigest), BrokerManifestDigest: string(broker.Metadata().ManifestDigest), ClientCatalogDigest: clients.Digest(), ContextKey: ssohttp.KeyRef{ID: "demo-context", FromEnv: "DEMO_SSO_CONTEXT"}, GrantKey: ssohttp.KeyRef{ID: "demo-grant", FromEnv: "DEMO_SSO_GRANT"}})
	if e != nil {
		return e
	}
	cfg.SSO = vs.SSO{AppDSNEnv: "DEMO_SSO_APP_DSN", RecoveryEpoch: s.Epochs["sso"], Clients: cf, Runtime: rf}
	manifest := string(core.Metadata().ManifestDigest)
	cfg.Data.MetadataPolicy, e = writeJSON(s.file("ops/metadata-policy.json"), rpcmetadatapolicy.Source{APIVersion: rpcmetadatapolicy.APIVersion, Kind: rpcmetadatapolicy.Kind, BundleManifestDigest: manifest, AnonymousMethods: []string{}})
	if e != nil {
		return e
	}
	cfg.Data.StatePolicy, e = writeJSON(s.file("ops/state-policy.json"), rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: manifest, AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}, LinkedWalletBasics: true})
	if e != nil {
		return e
	}
	cfg.Data.HistoryPolicy, e = writeJSON(s.file("ops/history-policy.json"), rpchistorypolicy.Source{APIVersion: rpchistorypolicy.APIVersion, Kind: rpchistorypolicy.Kind, BundleManifestDigest: manifest, AnonymousMethods: []string{}})
	if e != nil {
		return e
	}
	pinned, e := writeJSON(s.file("ops/server.json"), cfg)
	if e != nil {
		return e
	}
	if _, e = writeBytes(s.file("ops/server.sha256"), []byte(pinned.Digest+"\n")); e != nil {
		return e
	}
	env := map[string]string{}
	for _, key := range []string{"DEMO_ACCESS_PRIVATE", "OPS_BROKER_REFRESH_DEMO", "OPS_BROKER_ENCRYPTION_DEMO", "DEMO_SSO_CONTEXT", "DEMO_SSO_GRANT", "DEMO_EXPLORER_SECRET", "DEMO_ADMISSION_CURSOR", "DEMO_ADMIN_CURSOR", "DEMO_RENDER_KEY", "DEMO_DATA_CURSOR", "DEMO_INDEX_CURSOR", "DEMO_INDEX_PSEUDONYM"} {
		env[key] = s.Secrets[key]
	}
	for key, pair := range map[string][2]string{"DEMO_BROKER_APP_DSN": {"identity", "demo_identity_app"}, "DEMO_BROKER_PROOF_DSN": {"identity", "demo_identity_proof"}, "DEMO_SSO_APP_DSN": {"sso", "demo_sso_app"}, "DEMO_WALLET_APP_DSN": {"wallet", "demo_wallet_app"}, "DEMO_WALLET_READER_DSN": {"wallet", "demo_wallet_reader"}, "DEMO_ADMISSION_APP_DSN": {"admission", "demo_admission_app"}, "DEMO_ADMISSION_READER_DSN": {"admission", "demo_admission_reader"}, "DEMO_FACTS_DSN": {"admission", "demo_facts"}, "DEMO_NAMESPACE_DSN": {"admission", "demo_namespace"}, "DEMO_DISCLOSURE_APP_DSN": {"disclosure", "demo_disclosure_app"}, "DEMO_ACTIVITY_WRITER_DSN": {"activity", "demo_activity_writer"}, "DEMO_ACTIVITY_READER_DSN": {"activity", "demo_activity_reader"}, "DEMO_INDEX_DSN": {"index", "demo_index_reader"}} {
		env[key] = s.dsn(pair[0], pair[1])
	}
	env["SSL_CERT_FILE"] = s.file("ca.crt")
	if e = s.writeEnv("ops/env", env); e != nil {
		return e
	}
	pub := source.Issuers[0].Keys[0]
	explorer := map[string]any{"apiVersion": "ops.explorer-sso/v2", "kind": "ExplorerSSO", "appOrigin": s.ExplorerOrigin(), "opsOrigin": s.OPSOrigin(), "callbackURI": s.ExplorerOrigin() + "/api/auth/callback", "clientId": "explorer", "clientSecret": map[string]string{"fromEnv": "DEMO_EXPLORER_SECRET"}, "issuer": s.OPSOrigin(), "audience": "core", "keys": []map[string]string{{"id": pub.Kid, "x": pub.X}}, "profiles": appProfiles, "stateKey": map[string]string{"id": "demo-state", "fromEnv": "E2B_STATE"}, "tokenKey": map[string]string{"id": "demo-token", "fromEnv": "E2B_TOKEN"}, "recoveryEpoch": s.Epochs["sso"], "limits": map[string]any{"maxContexts": 200000, "maxCipherBytes": 1 << 30, "maxMetadataBytes": 512 << 20}, "network": map[string]string{"chainId": ChainID, "genesisHash": s.GenesisHash}, "retention": map[string]any{"enabled": true, "batchSize": 100, "intervalMillis": 1000}}
	ef, e := writeJSON(s.file("explorer/source.json"), explorer)
	if e != nil {
		return e
	}
	if _, e = writeBytes(s.file("explorer/source.sha256"), []byte(strings.TrimPrefix(ef.Digest, "sha256:")+"\n")); e != nil {
		return e
	}
	appEnv := map[string]string{"EXPLORER_AUTH_PROTOCOL": "ops-v2", "EXPLORER_SSO_SOURCE": ef.Path, "EXPLORER_SSO_SOURCE_SHA256": strings.TrimPrefix(ef.Digest, "sha256:"), "EXPLORER_SSO_APP_DSN": s.dsn("explorer", "explorer_sso_app"), "DEMO_EXPLORER_SECRET": s.Secrets["DEMO_EXPLORER_SECRET"], "E2B_STATE": s.Secrets["E2B_STATE"], "E2B_TOKEN": s.Secrets["E2B_TOKEN"], "SSL_CERT_FILE": s.file("ca.crt"), "API_PORT": fmt.Sprint(s.Ports.ExplorerAPI)}
	if e = s.writeEnv("explorer/env", appEnv); e != nil {
		return e
	}
	if e = s.writeEnv("private/explorer-admin.env", map[string]string{"EXPLORER_SSO_OWNER_DSN": s.dsn("explorer", "postgres"), "EXPLORER_SSO_SOURCE": ef.Path, "EXPLORER_SSO_SOURCE_SHA256": strings.TrimPrefix(ef.Digest, "sha256:")}); e != nil {
		return e
	}
	return nil
}
func Revision(ctx context.Context, root, walletOutput string, grant bool) error {
	root, e := canonicalRoot(root)
	if e != nil {
		return e
	}
	s, e := readState(root)
	if e != nil || !s.Configured {
		return ErrInvalid
	}
	s.ReaderGrant = grant
	if walletOutput != "" {
		s.WalletOutput = walletOutput
	}
	if e = save(s); e != nil {
		return e
	}
	return Configure(ctx, root, walletOutput)
}
