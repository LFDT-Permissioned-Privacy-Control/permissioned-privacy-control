package v2demo

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/operational/explorerindex"
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
	{"index", []string{"demo_index_writer", "demo_index_reader"}},
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
	u := url.URL{Scheme: "postgres", Host: fmt.Sprintf("127.0.0.1:%d", s.Ports.Postgres), User: url.UserPassword(role, password), Path: "/ops_v2_demo_" + database, RawQuery: "sslmode=disable"}
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
	owner, e := pgx.Connect(ctx, s.dsn("postgres", "postgres"))
	if e != nil {
		return e
	}
	defer owner.Close(ctx)
	for _, d := range databases {
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
	return s.writeEnv("indexer.env", map[string]string{"DATABASE_URL": s.dsn("index", "demo_index_writer"), "RPC_URL": s.RPCURL(), "GRPC_LISTEN_ADDR": fmt.Sprintf("127.0.0.1:%d", s.Ports.IndexerGRPC), "API_PORT": fmt.Sprint(s.Ports.Indexer), "METRICS_LISTEN_ADDR": fmt.Sprintf("127.0.0.1:%d", s.Ports.IndexerMetrics), "POLL_INTERVAL": "1s", "START_BLOCK": "0", "RPC_WORKERS": "2", "RPC_RATE_LIMIT": "50", "DB_BATCH_SIZE": "100", "TOKEN_METADATA_WORKERS": "1", "BALANCE_WORKERS": "1", "ENABLE_ASYNC_BALANCE": "false", "ENABLE_TRACING": "true", "TRACE_RATE_LIMIT": "10", "TRACE_WORKERS": "1", "METRICS_ENABLED": "false", "PPROF_ENABLED": "false", "USE_SOURCIFY_FALLBACK": "false", "LOG_LEVEL": "info"})
}
func grantIndex(ctx context.Context, s State) error {
	c, e := pgx.Connect(ctx, s.dsn("index", "postgres"))
	if e != nil {
		return e
	}
	defer c.Close(ctx)
	columns, e := explorerindex.ReadColumns()
	if e != nil {
		return e
	}
	// The real indexer owns its migrations. Wait only for its required public
	// columns; never manufacture an index schema or a synthetic indexed row.
	tables, names := []string{}, []string{}
	for table, selected := range columns {
		for _, column := range selected {
			tables = append(tables, table)
			names = append(names, column)
		}
	}
	wait, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	for {
		var ready bool
		e = c.QueryRow(wait, `SELECT NOT EXISTS(SELECT 1 FROM unnest($1::text[],$2::text[]) required(table_name,column_name) WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_class r ON r.relnamespace=n.oid JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid WHERE n.nspname='public' AND r.relname=required.table_name AND a.attname=required.column_name AND a.attnum>0 AND NOT a.attisdropped))`, tables, names).Scan(&ready)
		if e != nil {
			return e
		}
		if ready {
			break
		}
		select {
		case <-wait.Done():
			return fmt.Errorf("real indexer required schema is not ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e = sql(ctx, c, `REVOKE CREATE ON SCHEMA public FROM PUBLIC; REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO demo_index_reader`); e != nil {
		return e
	}
	for table, names := range columns {
		quoted := make([]string, len(names))
		for i, name := range names {
			quoted[i] = pgx.Identifier{name}.Sanitize()
		}
		if len(quoted) == 0 {
			return ErrInvalid
		}
		if e = sql(ctx, c, "GRANT SELECT ("+strings.Join(quoted, ",")+") ON public."+pgx.Identifier{table}.Sanitize()+" TO demo_index_reader"); e != nil {
			return e
		}
	}
	return nil
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
