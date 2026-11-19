package v2demo

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5"
)

type databaseSpec struct {
	name  string
	roles []string
}

var databases = []databaseSpec{
	{"identity", []string{"demo_identity_app", "demo_identity_proof", "demo_identity_retention"}},
	{"sso", []string{"demo_sso_app", "demo_sso_retention"}},
	{"wallet", []string{"demo_wallet_app", "demo_wallet_reader", "demo_wallet_retention"}},
	{"admission", []string{"demo_admission_app", "demo_admission_reader", "demo_admission_retention", "demo_observer", "demo_facts", "demo_namespace"}},
	{"disclosure", []string{"demo_disclosure_app", "demo_disclosure_retention"}},
	{"activity", []string{"demo_activity_writer", "demo_activity_reader", "demo_activity_retention"}},
	{"index", []string{"demo_index_writer"}},
	{"explorer", []string{"explorer_sso_app"}},
}

func (s State) rolePassword(role string) string {
	h := hmac.New(sha256.New, []byte(s.Secrets["DEMO_ROLE_SEED"]))
	h.Write([]byte("isolated-v2-demo-role:" + role))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (s State) dsn(database, role string) string {
	password := s.rolePassword(role)
	if role == "postgres" {
		password = s.Secrets["DEMO_POSTGRES_PASSWORD"]
	}
	host := "127.0.0.1"
	if s.PrivateNetwork {
		host = "operational-postgres"
		if database == "index" {
			host = "indexer-postgres"
		}
		if database == "explorer" {
			host = "explorer-postgres"
		}
	}
	u := url.URL{Scheme: "postgres", Host: fmt.Sprintf("%s:%d", host, s.Ports.Postgres), User: url.UserPassword(role, password), Path: "/ops_v2_demo_" + database, RawQuery: "sslmode=disable"}
	if database == "postgres" {
		u.Path = "/postgres"
	}
	return u.String()
}
func sql(ctx context.Context, c *pgx.Conn, statement string, args ...any) error {
	_, e := c.Exec(ctx, statement, args...)
	return e
}
func PrepareDatabases(ctx context.Context, root string) error {
	root, e := canonicalRoot(root)
	if e != nil {
		return e
	}
	s, e := readState(root)
	if e != nil {
		return e
	}
	operationalOwner, e := pgx.Connect(ctx, s.dsn("postgres", "postgres"))
	if e != nil {
		return e
	}
	defer operationalOwner.Close(ctx)
	for _, d := range databases {
		owner := operationalOwner
		if (d.name == "index" || d.name == "explorer") && s.PrivateNetwork {
			u, _ := url.Parse(s.dsn(d.name, "postgres"))
			u.Path = "/postgres"
			owner, e = pgx.Connect(ctx, u.String())
			if e != nil {
				return e
			}
			defer owner.Close(ctx)
		}
		for _, role := range d.roles {
			var exists bool
			if e = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=$1)`, role).Scan(&exists); e != nil {
				return e
			}
			if !exists {
				if e = sql(ctx, owner, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOINHERIT PASSWORD '"+s.rolePassword(role)+"'"); e != nil {
					return e
				}
			}
		}
		name := "ops_v2_demo_" + d.name
		var exists bool
		if e = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=$1)`, name).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			command := "CREATE DATABASE " + pgx.Identifier{name}.Sanitize()
			if d.name == "index" {
				command += " OWNER demo_index_writer"
			}
			if e = sql(ctx, owner, command); e != nil {
				return e
			}
		}
		// Each service's operational credentials can open only its own database.
		// In particular, none of the credentials delivered to OPS can open the
		// indexer's private chain-data database, even on this shared demo server.
		if e = sql(ctx, owner, "REVOKE CONNECT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" FROM PUBLIC"); e != nil {
			return e
		}
		for _, role := range d.roles {
			if e = sql(ctx, owner, "GRANT CONNECT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" TO "+pgx.Identifier{role}.Sanitize()); e != nil {
				return e
			}
		}
		c, e := pgx.Connect(ctx, s.dsn(d.name, "postgres"))
		if e != nil {
			return e
		}
		e = sql(ctx, c, "REVOKE CREATE ON SCHEMA public FROM PUBLIC")
		c.Close(ctx)
		if e != nil {
			return e
		}
	}
	return writeIndexerEnvironment(s)
}

// Indexer DB credentials are delivered only to the indexer and its offline
// provisioning command. OPS receives the gRPC endpoint and pinned source identity.
func writeIndexerEnvironment(s State) error {
	env := map[string]string{"DATABASE_URL": s.dsn("index", "demo_index_writer"), "RPC_URL": s.RPCURL(), "GRPC_LISTEN_ADDR": s.indexerAddress(), "API_PORT": fmt.Sprint(s.Ports.Indexer), "METRICS_LISTEN_ADDR": fmt.Sprintf("127.0.0.1:%d", s.Ports.IndexerMetrics), "POLL_INTERVAL": "1s", "START_BLOCK": "0", "RPC_WORKERS": "2", "RPC_RATE_LIMIT": "50", "DB_BATCH_SIZE": "100", "TOKEN_METADATA_WORKERS": "1", "BALANCE_WORKERS": "1", "ENABLE_ASYNC_BALANCE": "false", "ENABLE_TRACING": "true", "TRACE_RATE_LIMIT": "10", "TRACE_WORKERS": "1", "METRICS_ENABLED": "false", "PPROF_ENABLED": "false", "USE_SOURCIFY_FALLBACK": "false", "LOG_LEVEL": "info"}
	return s.writeEnv("indexer.env", env)
}
func emptyTable(ctx context.Context, dsn, table string) (bool, error) {
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return false, e
	}
	defer c.Close(ctx)
	var exists bool
	e = c.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+")").Scan(&exists)
	return !exists, e
}
