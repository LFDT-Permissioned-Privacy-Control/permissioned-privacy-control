package v2demo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	cf "privacy-proxy/internal/creationfacts"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
	hn "privacy-proxy/internal/historynamespace"
	ib "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/disclosuresql"
	"privacy-proxy/internal/operational/explorerindex"
	"privacy-proxy/internal/operational/identitysql"
	"privacy-proxy/internal/operational/ssosql"
	vs "privacy-proxy/internal/operational/v2server"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/rpcexecution"
	sm "privacy-proxy/internal/ssotransaction"
	"privacy-proxy/internal/walletops"
)

func actualNode(ctx context.Context, s State) (*types.Header, *types.Header, error) {
	c, e := ethclient.DialContext(ctx, s.RPCURL())
	if e != nil {
		return nil, nil, e
	}
	defer c.Close()
	chain, e := c.ChainID(ctx)
	if e != nil || chain.String() != ChainID {
		return nil, nil, ErrInvalid
	}
	genesis, e := c.HeaderByNumber(ctx, big.NewInt(0))
	if e != nil {
		return nil, nil, e
	}
	head, e := c.HeaderByNumber(ctx, nil)
	if e != nil {
		return nil, nil, e
	}
	if s.GenesisHash != "" && s.GenesisHash != genesis.Hash().Hex() {
		return nil, nil, ErrInvalid
	}
	return genesis, head, nil
}
func Configure(ctx context.Context, root, walletOutput string) error {
	root, e := canonicalRoot(root)
	if e != nil {
		return e
	}
	s, e := readState(root)
	if e != nil {
		return e
	}
	if walletOutput != "" {
		s.WalletOutput = walletOutput
	}
	genesis, head, e := actualNode(ctx, s)
	if e != nil {
		return fmt.Errorf("actual node: %w", e)
	}
	s.GenesisHash = genesis.Hash().Hex()
	core, broker, cs, bs, e := bundles(ctx, s)
	if e != nil {
		return fmt.Errorf("approved files: %w", e)
	}
	cfg := vs.Config{APIVersion: "ops.server/v2", Kind: "OperationalServer", Listen: fmt.Sprintf("127.0.0.1:%d", s.Ports.OPS), TLSCertificateFile: s.file("tls.crt"), TLSPrivateKeyFile: s.file("tls.key"), WebDirectory: "/app/web", ExplorerOrganizationID: Organization, Core: cs, BrokerSelection: bs}
	network := networkidentity.Binding{Environment: Environment, ChainID: ChainID, GenesisHash: s.GenesisHash, DeploymentID: Deployment}
	networkKey, e := network.Key()
	if e != nil {
		return e
	}
	binding := admission.NetworkBinding(network)
	auth, _ := broker.AuthBroker()
	brokerBinding := ib.ServiceBinding{Environment: Environment, DeploymentID: Deployment, Origin: s.OPSOrigin()}
	ns, e := brokerBinding.Namespace(auth.Issuer().Issuer)
	if e != nil {
		return e
	}
	brokerScope := ib.Scope{Namespace: ns, State: ib.ExpectedState{RecoveryEpoch: s.Epochs["broker"]}}
	cfg.Broker = vs.Broker{DeploymentID: Deployment, RecoveryEpoch: s.Epochs["broker"], AppDSNEnv: "DEMO_BROKER_APP_DSN", ProofDSNEnv: "DEMO_BROKER_PROOF_DSN", SigningPrivateKeyEnv: "DEMO_ACCESS_PRIVATE"}
	wbind := walletops.ServiceBinding{ServiceOrigin: s.OPSOrigin(), Environment: Environment, ChainID: ChainID, GenesisHash: s.GenesisHash, DeploymentID: Deployment}
	cfg.Wallet = vs.Wallet{AppDSNEnv: "DEMO_WALLET_APP_DSN", ServiceOrigin: s.OPSOrigin(), DeploymentID: Deployment, GenesisHash: s.GenesisHash, Generation: s.Epochs["wallet"], CoverageDigest: admission.Digest(walletsql.EmptyCoverage()).String()}
	cfg.Data.WalletReaderDSNEnv = "DEMO_WALLET_READER_DSN"
	fn := cf.Network{Key: cf.Digest(networkKey), Environment: Environment, ChainID: ChainID, Genesis: genesis.Hash(), Deployment: Deployment}
	fstate := cf.State{Generation: s.Epochs["admission"], Coverage: cf.Digest(admissionsql.EmptyCoverage())}
	end := uint64(s.CreatedAt + 366*86400)
	reference := cf.Source{Network: fn, URL: s.RPCURL(), Profile: rpcexecution.IncludedProfileID, PragueStart: 1, PragueEnd: end}
	source := reference
	source.Organization = Organization
	source.Profile = rpcexecution.LifecycleSignedProfileID
	sources := []cf.Source{source}
	set, e := cf.SourceSet(sources)
	if e != nil {
		return e
	}
	gate := creationcapture.Metadata{Network: fn, State: fstate, Reference: reference.Digest(), SourceSet: set}
	cfg.Data.DefaultNode = vs.Endpoint{URL: s.RPCURL(), PragueStart: 1, PragueEnd: end}
	cfg.Data.Nodes = []vs.Node{{OrganizationID: Organization, URL: s.RPCURL(), PragueStart: 1, PragueEnd: end, AllowUnauthenticated: true, Credentials: []vs.Credential{}}}
	cfg.Data.NodeSigning = false
	cfg.Data.Admission = vs.Admission{AppDSNEnv: "DEMO_ADMISSION_APP_DSN", ReaderDSNEnv: "DEMO_ADMISSION_READER_DSN", FactsDSNEnv: "DEMO_FACTS_DSN", Generation: s.Epochs["admission"], CoverageDigest: admissionsql.EmptyCoverage().String(), AddressSourceSetDigest: digest(set[:]), AddressReferenceDigest: digest(gate.Reference[:]), CursorKeyEnv: "DEMO_ADMISSION_CURSOR", CursorKeyID: "demo"}
	era := hn.ModelEra{EntryNumber: 0, EntryHash: hn.Hash(genesis.Hash()), EntryTimestamp: genesis.Time, EndTimestampExclusive: end}
	cfg.Protected = vs.Protected{AppDSNEnv: "DEMO_DISCLOSURE_APP_DSN", StoreEpoch: s.Epochs["disclosure"], NamespaceDSNEnv: "DEMO_NAMESPACE_DSN", NamespaceEra: vs.Era{EntryNumber: 0, EntryHash: s.GenesisHash, EntryTimestamp: genesis.Time, EndTimestampExclusive: end}, Nodes: []vs.ProtectedNode{{OrganizationID: Organization, Endpoint: cfg.Data.DefaultNode}}, AdminCursorKeys: vs.KeyRing{Active: vs.Key{ID: "demo-admin", FromEnv: "DEMO_ADMIN_CURSOR"}}, RenderKeys: vs.KeyRing{Active: vs.Key{ID: "demo-render", FromEnv: "DEMO_RENDER_KEY"}}, DataCursorKeys: vs.KeyRing{Active: vs.Key{ID: "demo-data", FromEnv: "DEMO_DATA_CURSOR"}}}
	ssoNS, e := sm.NamespaceFor(sm.Digest(ns), s.OPSOrigin())
	if e != nil {
		return e
	}
	ssoReg := ssosql.Registration{Namespace: ssoNS, BrokerNamespace: sm.Digest(ns), Epoch: s.Epochs["sso"], BrokerRecoveryEpoch: s.Epochs["broker"], Limits: sm.DefaultLimits(), Roles: ssosql.Roles{App: "demo_sso_app", Retention: "demo_sso_retention"}}
	if !s.Configured {
		if e = identitysql.MigrateV2(ctx, s.dsn("identity", "postgres"), "demo_identity_app", "demo_identity_proof", "demo_identity_retention", brokerScope, true); e != nil {
			return fmt.Errorf("broker migration: %w", e)
		}
		if e = ssosql.Migrate(ctx, s.dsn("sso", "postgres"), ssoReg.Roles, true); e != nil {
			return e
		}
		if e = ssosql.Initialize(ctx, s.dsn("sso", "postgres"), ssoReg, true); e != nil {
			return e
		}
		if e = walletsql.Migrate(ctx, s.dsn("wallet", "postgres"), "demo_wallet_app", "demo_wallet_reader", "demo_wallet_retention"); e != nil {
			return e
		}
		empty, e := emptyTable(ctx, s.dsn("wallet", "postgres"), "ops_wallet_v2.store_state")
		if e != nil {
			return e
		}
		if empty {
			if e = walletsql.BootstrapEmpty(ctx, s.dsn("wallet", "postgres"), wbind, s.Epochs["wallet"]); e != nil {
				return e
			}
		}
		if e = admissionsql.MigrateCreationObserver(ctx, s.dsn("admission", "postgres"), "demo_admission_app", "demo_admission_reader", "demo_admission_retention", "demo_observer", "demo_facts"); e != nil {
			return e
		}
		empty, e = emptyTable(ctx, s.dsn("admission", "postgres"), "ops_admission_v2.network_state")
		if e != nil {
			return e
		}
		if empty {
			if e = admissionsql.BootstrapEmpty(ctx, s.dsn("admission", "postgres"), binding, s.Epochs["admission"]); e != nil {
				return e
			}
		}
		empty, e = emptyTable(ctx, s.dsn("admission", "postgres"), "ops_admission_v2.creation_observer_state")
		if e != nil {
			return e
		}
		if empty {
			floor := cf.Header{Number: head.Number.Uint64(), Hash: head.Hash(), Parent: head.ParentHash, Timestamp: head.Time}
			if e = admissionsql.BootstrapCreationObserver(ctx, s.dsn("admission", "postgres"), binding, admission.ExpectedState{Generation: s.Epochs["admission"], Coverage: admissionsql.EmptyCoverage()}, gate, floor); e != nil {
				return e
			}
		}
		if e = admissionsql.MigrateNamespace(ctx, s.dsn("admission", "postgres"), "demo_namespace", true); e != nil {
			return e
		}
		empty, e = emptyTable(ctx, s.dsn("admission", "postgres"), "ops_history_namespace_v1.namespace_network_state")
		if e != nil {
			return e
		}
		if empty {
			if e = admissionsql.BootstrapNamespace(ctx, s.dsn("admission", "postgres"), binding, s.Epochs["admission"], era, hn.DefaultCapacityLimits(), true, true); e != nil {
				return e
			}
			metadata, e := admissionsql.ReadNamespaceOwnerMetadata(ctx, s.dsn("admission", "postgres"), binding)
			if e != nil {
				return e
			}
			emptyDigest := sha256.Sum256([]byte("isolated-new-demo-empty-supplemental-archive:" + s.GenesisHash))
			if e = admissionsql.FinalizeNamespaceRecovery(ctx, s.dsn("admission", "postgres"), binding, metadata.State, hn.Digest(emptyDigest), true, true, 60); e != nil {
				return e
			}
		}
		if e = disclosuresql.Migrate(ctx, s.dsn("disclosure", "postgres"), "demo_disclosure_app", "demo_disclosure_retention"); e != nil {
			return e
		}
		if e = initializeActivity(ctx, &s, network); e != nil {
			return e
		}
	}
	if e = grantIndex(ctx, s); e != nil {
		return fmt.Errorf("actual index schema minimum grants: %w", e)
	}
	indexDSN := s.dsn("index", "demo_index_reader")
	iref, e := explorerindex.ConnectionReference(indexDSN)
	if e != nil {
		return e
	}
	cfg.Data.Index = vs.Index{ReaderDSNEnv: "DEMO_INDEX_DSN", SourceReferenceDigest: digest(iref[:]), ConfiguredEpoch: s.Epochs["index"], CursorKeyEnv: "DEMO_INDEX_CURSOR", PseudonymKeyEnv: "DEMO_INDEX_PSEUDONYM"}
	conf := sha256.Sum256([]byte("native-v2-local-demo-activity:" + s.GenesisHash))
	cfg.Data.Activity = vs.Activity{WriterDSNEnv: "DEMO_ACTIVITY_WRITER_DSN", ReaderDSNEnv: "DEMO_ACTIVITY_READER_DSN", SourceID: s.Epochs["activitySource"], ProducerID: s.Epochs["activityProducer"], Generation: s.ActivityGeneration, ConfigurationDigest: digest(conf[:]), BufferDirectory: "/var/lib/ops/activity"}
	if e = runtimeFiles(ctx, s, core, broker, &cfg); e != nil {
		return e
	}
	if e = observerFiles(s, reference, sources); e != nil {
		return e
	}
	s.Configured = true
	return save(s)
}
func digest(b []byte) string { return "sha256:" + hex.EncodeToString(b) }
func initializeActivity(ctx context.Context, s *State, network networkidentity.Binding) error {
	dsn := s.dsn("activity", "postgres")
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return e
	}
	defer c.Close(ctx)
	migrator, e := migrate.NewMigrator(ctx, c, "schema_version_audit")
	if e != nil {
		return e
	}
	if e = migrator.LoadMigrations(migrationsaudit.FS); e != nil {
		return e
	}
	if e = migrator.Migrate(ctx); e != nil {
		return e
	}
	roles := activitysql.RoleNames{Writer: "demo_activity_writer", Reader: "demo_activity_reader", Retention: "demo_activity_retention"}
	if e = activitysql.Migrate(ctx, dsn, roles.Writer, roles.Reader, roles.Retention, true); e != nil {
		return e
	}
	conf := sha256.Sum256([]byte("native-v2-local-demo-activity:" + s.GenesisHash))
	reg := activitysql.Registration{Network: network, SourceID: s.Epochs["activitySource"], Configuration: conf, Limits: activitysql.DefaultStorageLimits(), Roles: roles}
	if e = activitysql.Initialize(ctx, dsn, reg, true); e != nil {
		return e
	}
	key, _ := network.Key()
	status, e := activitysql.Status(ctx, dsn, key, reg.SourceID)
	if e != nil {
		return e
	}
	s.ActivityGeneration = status.Metadata.Generation
	return nil
}
func observerFiles(s State, reference cf.Source, sources []cf.Source) error {
	if _, e := writeJSON(s.file("observer/sources.json"), sources); e != nil {
		return e
	}
	args := []string{"run", "--dsn-env", "DEMO_OBSERVER_DSN", "--environment", Environment, "--chain-id", ChainID, "--genesis-hash", s.GenesisHash, "--deployment-id", Deployment, "--generation", s.Epochs["admission"], "--coverage-digest", admissionsql.EmptyCoverage().String(), "--reference-url", reference.URL, "--prague-start", "1", "--prague-end", fmt.Sprint(reference.PragueEnd), "--sources-file", s.file("observer/sources.json"), "--caught-up-assertion", "operator-managed-canonical-head/v1"}
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
	}
	script := "#!/bin/sh\nset -eu\nexec ops-creation-observer " + strings.Join(quoted, " ") + "\n"
	file, e := writeBytes(s.file("observer/run.sh"), []byte(script))
	if e != nil {
		return e
	}
	if e = os.Chmod(file.Path, 0700); e != nil {
		return e
	}
	return s.writeEnv("observer/env", map[string]string{"DEMO_OBSERVER_DSN": s.dsn("admission", "demo_observer")})
}
