package identitysql

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	b "privacy-proxy/internal/identitybroker"
)

//go:embed migrations/002.sql
var schemaSQLV2 string

//go:embed schema/catalog-v1.json
var catalogV1 []byte

//go:embed schema/catalog-v2.json
var catalogV2 []byte

func SchemaChecksum() string {
	return b.Hash("ops.identity.schema/v2", []byte(schemaSQL), []byte(schemaSQLV2)).String()
}

const catalogQuery = `SELECT json_build_object(
 'columns',(SELECT json_agg(x ORDER BY table_name,attnum) FROM(SELECT c.relname table_name,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod) type,a.attnotnull not_null,pg_get_expr(d.adbin,d.adrelid) default_expr FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='ops_identity_v2' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped)x),
 'constraints',(SELECT json_agg(x ORDER BY table_name,name) FROM(SELECT c.conrelid::regclass::text table_name,c.conname name,c.contype type,c.convalidated validated,c.condeferrable deferrable,c.condeferred deferred,pg_get_constraintdef(c.oid,true) definition FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='ops_identity_v2')x),
 'indexes',(SELECT json_agg(x ORDER BY name) FROM(SELECT c.relname name,pg_get_indexdef(c.oid) definition,i.indisvalid valid,i.indisready ready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_identity_v2')x),
 'triggers',(SELECT json_agg(x ORDER BY name) FROM(SELECT t.tgname name,t.tgrelid::regclass::text table_name,t.tgenabled enabled,pg_get_triggerdef(t.oid,true) definition FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_identity_v2' AND NOT t.tgisinternal)x),
 'functions',(SELECT json_agg(x ORDER BY name) FROM(SELECT p.proname name,p.prosecdef security_definer,p.provolatile volatility,p.proconfig config,l.lanname language,p.prosrc body FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='ops_identity_v2')x))`

func checkCatalog(ctx context.Context, q querier, expected []byte, version int) error {
	var actual []byte
	if q.QueryRow(ctx, catalogQuery).Scan(&actual) != nil || len(actual) > 128<<10 {
		return b.ErrUnavailable
	}
	var a, z any
	if json.Unmarshal(actual, &a) != nil || json.Unmarshal(expected, &z) != nil {
		return b.ErrUnavailable
	}
	aa, _ := json.Marshal(a)
	zz, _ := json.Marshal(z)
	if !bytes.Equal(aa, zz) {
		return b.ErrUnavailable
	}
	var good bool
	// Reject unknown relations/overloads and deployment owner changes separately
	// from portable definition bytes. Owners are trusted offline identities.
	err := q.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer/10000=16
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_identity_v2' AND (c.relkind NOT IN('r','i') OR c.relowner<>n.nspowner OR c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ops_identity_v2' AND (p.proowner<>n.nspowner OR pg_get_function_identity_arguments(p.oid)<>'' OR pg_get_function_result(p.oid)<>'trigger'))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='ops_identity_v2' AND a.grantee=0)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='ops_identity_v2' AND a.grantee=0)
 AND NOT EXISTS(SELECT 1 FROM pg_attribute c JOIN pg_class t ON t.oid=c.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace CROSS JOIN LATERAL aclexplode(CASE WHEN cardinality(c.attacl)>0 THEN c.attacl ELSE NULL::aclitem[] END) a WHERE n.nspname='ops_identity_v2' AND a.grantee=0)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='ops_identity_v2' AND a.grantee=0)
 AND (SELECT count(*) FROM ops_identity_v2.metadata)=1
 AND (SELECT schema_version=$1 FROM ops_identity_v2.metadata WHERE singleton)`, version).Scan(&good)
	if err != nil || !good {
		return b.ErrUnavailable
	}
	return nil
}
func checkSchemaV1(ctx context.Context, q querier) error {
	if err := checkSchemaV1Legacy(ctx, q); err != nil {
		return err
	}
	return checkCatalog(ctx, q, catalogV1, 1)
}
func checkSchema(ctx context.Context, q querier) error {
	var good bool
	if q.QueryRow(ctx, `SELECT schema_version=2 AND migration_checksum=$1 FROM ops_identity_v2.metadata WHERE singleton`, SchemaChecksum()).Scan(&good) != nil || !good {
		return b.ErrUnavailable
	}
	return checkCatalog(ctx, q, catalogV2, 2)
}

// MigrateV2 runs only with offline owner credentials and a drained deployment.
// Readiness is committed false before DDL/ACL work; a failed/uncertain step may
// be retried only from one of the exact known v1/v2 shapes. Existing Azure
// ciphertext, family identity, namespace and epoch are retained byte for byte.
func MigrateV2(ctx context.Context, dsn, appRole, proofRole, retentionRole string, scope b.Scope, allWorkersDrained bool) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	roles := []string{appRole, proofRole, retentionRole}
	seen := map[string]bool{}
	if strings.TrimSpace(dsn) == "" || !scope.Valid() || !allWorkersDrained {
		return b.ErrInvalid
	}
	for _, r := range roles {
		if !rolePattern.MatchString(r) || seen[r] {
			return b.ErrInvalid
		}
		seen[r] = true
	}
	conn, err := offlineConnection(ctx, dsn)
	if err != nil {
		return err
	}
	var exists *string
	err = conn.QueryRow(ctx, `SELECT to_regclass('ops_identity_v2.metadata')::text`).Scan(&exists)
	closeConnection(conn)
	if err != nil {
		return b.ErrUnavailable
	}
	if exists == nil {
		if err = Migrate(ctx, dsn, appRole, retentionRole, scope); err != nil {
			return err
		}
	}
	if err = offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var version int
		if tx.QueryRow(ctx, `SELECT schema_version FROM ops_identity_v2.metadata WHERE singleton`).Scan(&version) != nil {
			return b.ErrUnavailable
		}
		if version == 1 {
			if e := checkSchemaV1(ctx, tx); e != nil {
				return e
			}
		} else if version == 2 {
			if e := checkSchema(ctx, tx); e != nil {
				return e
			}
		} else {
			return b.ErrUnavailable
		}
		var same bool
		if tx.QueryRow(ctx, `SELECT namespace=$1 AND recovery_epoch=$2::uuid FROM ops_identity_v2.metadata WHERE singleton`, scope.Namespace.String(), scope.State.RecoveryEpoch).Scan(&same) != nil || !same {
			return b.ErrConflict
		}
		_, e := tx.Exec(ctx, `UPDATE ops_identity_v2.metadata SET ready=false,updated_at=clock_timestamp() WHERE singleton`)
		return e
	}); err != nil {
		return err
	}
	if err = offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var version int
		var ready bool
		if tx.QueryRow(ctx, `SELECT schema_version,ready FROM ops_identity_v2.metadata WHERE singleton`).Scan(&version, &ready) != nil || ready {
			return b.ErrUnavailable
		}
		if version == 1 {
			if e := checkSchemaV1(ctx, tx); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, schemaSQLV2); e != nil {
				return b.ErrUnavailable
			}
			if _, e := tx.Exec(ctx, `UPDATE ops_identity_v2.metadata SET schema_version=2,migration_checksum=$1,ready=false,updated_at=clock_timestamp() WHERE singleton`, SchemaChecksum()); e != nil {
				return b.ErrUnavailable
			}
			if _, e := tx.Exec(ctx, `ALTER TABLE ops_identity_v2.metadata VALIDATE CONSTRAINT metadata_schema_version_check`); e != nil {
				return b.ErrUnavailable
			}
		} else if version != 2 {
			return b.ErrUnavailable
		}
		if e := installV2ACL(ctx, tx, roles); e != nil {
			return e
		}
		return checkSchema(ctx, tx)
	}); err != nil {
		return err
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		if e := checkSchema(ctx, tx); e != nil {
			return e
		}
		for i, role := range roles {
			if e := checkV2Privileges(ctx, tx, role, []string{"app", "proof", "retention"}[i]); e != nil {
				return e
			}
		}
		var good bool
		if tx.QueryRow(ctx, `SELECT namespace=$1 AND recovery_epoch=$2::uuid AND NOT ready FROM ops_identity_v2.metadata WHERE singleton`, scope.Namespace.String(), scope.State.RecoveryEpoch).Scan(&good) != nil || !good {
			return b.ErrConflict
		}
		var challenges, offers, offerBytes int64
		if tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM ops_identity_v2.privado_challenges WHERE namespace=$1),(SELECT count(*) FROM ops_identity_v2.privado_offers WHERE namespace=$1),(SELECT COALESCE(sum(octet_length(proof_ciphertext)::bigint),0) FROM ops_identity_v2.privado_offers WHERE namespace=$1)`, scope.Namespace.String()).Scan(&challenges, &offers, &offerBytes) != nil || challenges > b.MaxPrivadoChallenges || offers > b.MaxPrivadoOffers || offerBytes > b.MaxPrivadoOfferBytes {
			return b.ErrUnavailable
		}
		_, e := tx.Exec(ctx, `UPDATE ops_identity_v2.metadata SET ready=true,updated_at=clock_timestamp() WHERE singleton`)
		return e
	})
}
