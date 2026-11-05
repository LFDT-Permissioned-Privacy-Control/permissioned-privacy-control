package db

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db/migrations"
	"privacy-proxy/internal/rbac"
)

func TestV2UpgradeFromMainPreservesPermissions(t *testing.T) {
	dsn, cleanup := SetupTestContainer(t)
	defer cleanup()
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	m, err := migrate.NewMigrator(ctx, conn, "schema_version")
	require.NoError(t, err)
	require.NoError(t, m.LoadMigrations(migrations.FS))
	require.Equal(t, "072_impersonation_log_indeterminate.sql", m.Migrations[71].Name)
	require.NoError(t, m.MigrateTo(ctx, 72))

	org, group := uuid.NewString(), uuid.NewString()
	_, err = conn.Exec(ctx, `INSERT INTO organizations(id,slug,name) VALUES($1,'v2-upgrade','V2 upgrade')`, org)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `INSERT INTO groups(id,org_id,slug,name,path) VALUES($1,$2,'members','Members','members')`, group, org)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims) VALUES($1,$2,ARRAY['eth_call','eth_sendTransaction'],ARRAY['deploy'])`, uuid.NewString(), group)
	require.NoError(t, err)

	// This is a source-history/schema rehearsal, not a deployed-binary upgrade
	// qualification. The migration prefix through 072 is shared with the local
	// main reference 9979b12c; no previous application binary runs in this test.
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := conn.Exec(ctx, query, args...)
		require.NoError(t, err)
	}
	secondGroup, member, authorID, reviewerID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO groups(id,org_id,slug,name,path) VALUES($1,$2,'expired','Expired membership','expired')`, secondGroup, org)
	for _, id := range []string{member, authorID, reviewerID} {
		exec(`INSERT INTO users(id,external_id,kyc,banned) VALUES($1,$2,true,$3)`, id, "did:upgrade:"+id, id == member)
	}
	exec(`INSERT INTO user_memberships(id,user_id,group_id,expires_at) VALUES($1,$2,$3,'2099-01-01')`, uuid.NewString(), member, group)
	exec(`INSERT INTO user_memberships(id,user_id,group_id,expires_at) VALUES($1,$2,$3,'2020-01-01')`, uuid.NewString(), member, secondGroup)
	exec(`INSERT INTO eth_address_links(did,eth_address,signature,message_hash,revoked,revoked_at)
        VALUES($1,'0x1111111111111111111111111111111111111111','stored-proof','stored-hash',false,NULL),
              ($1,'0x2222222222222222222222222222222222222222','stored-revoked-proof','stored-hash',true,'2026-01-01')`, "did:upgrade:"+member)
	exec(`INSERT INTO refresh_tokens(token_hash,subject,expires_at,revoked,revoked_at)
        VALUES('upgrade-refresh',$1,'2099-01-01',true,'2026-01-01')`, "did:upgrade:"+member)
	exec(`INSERT INTO revoked_tokens(token_id,subject,expires_at) VALUES('upgrade-access',$1,'2099-01-01')`, "did:upgrade:"+member)
	contract := uuid.NewString()
	exec(`INSERT INTO contracts(id,org_id,address,name,deployed_by_user_id,deployed_at,metadata)
        VALUES($1,$2,'0x3333333333333333333333333333333333333333','Observed deployment',$3,'2026-01-01','{"blockNumber":42}')`, contract, org, member)
	exec(`INSERT INTO contract_grants(id,contract_id,group_id,functions) VALUES($1,$2,$3,NULL)`, uuid.NewString(), contract, group)
	exec(`INSERT INTO contract_grants(id,contract_id,group_id,functions) VALUES($1,$2,$3,'[]')`, uuid.NewString(), contract, secondGroup)

	// Write the sentinel through the runtime audit writer, with a real chain;
	// migration SQL must neither invent approval evidence nor rewrite history.
	legacy, err := NewWithoutMigrate(dsn)
	require.NoError(t, err)
	chain := audit.NewHashChain("")
	legacy.SetRBACAuditChain(chain)
	require.NoError(t, legacy.CreateAuditLog(ctx, &rbac.AuditLogEntry{
		ActorID: &authorID, ActorExternalID: "did:upgrade:" + authorID,
		Action: "update", ResourceType: "group", ResourceID: &group, OrgID: &org,
		NewValue: map[string]any{"name": "Members"},
	}))
	require.NoError(t, legacy.Close())

	// Compare stored rows, including expiry/revocation timestamps, deployment
	// observations, and SQL NULL versus an empty function-rule array. Exclude
	// only the additive credential-source column introduced after version 072.
	snapshot := func() map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, table := range []string{"groups", "group_access", "contracts", "contract_grants", "users", "user_memberships", "eth_address_links", "refresh_tokens", "revoked_tokens", "rbac_audit_log"} {
			var rows string
			err := conn.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(t)-'rpc_api_key_source' ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM `+table+` t`).Scan(&rows)
			require.NoError(t, err)
			out[table] = rows
		}
		return out
	}
	before := snapshot()
	var auditCount int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM rbac_audit_log`).Scan(&auditCount))

	// Open the database exactly as the application does on upgrade. Main's
	// published migrations through 072 must not be reinterpreted as V2 ones.
	d, err := New(dsn)
	require.NoError(t, err)
	defer d.Close()
	require.Equal(t, before, snapshot(), "upgrade must retain operational facts, permission semantics and audit evidence")
	access, err := d.GetGroupAccess(ctx, group)
	require.NoError(t, err)
	require.Equal(t, []string{"eth_call", "eth_sendTransaction"}, access.AllowedMethods)
	require.Equal(t, []rbac.Claim{rbac.ClaimDeploy}, access.Claims)
	view, err := d.GetConfigurationContext(ctx, configuration.Scope{Kind: "organization", ID: org}, configuration.Groups)
	require.NoError(t, err)
	require.Zero(t, view.Source.BaseRevision, "upgrade must not activate a configuration")
	require.Len(t, view.Source.Spec.(configuration.GroupsSpec).Groups, 2)
	var invented int
	require.NoError(t, conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM configuration_revisions)+(SELECT count(*) FROM execution_policy_revisions)`).Scan(&invented))
	require.Zero(t, invented, "upgrade must not manufacture approved revisions")
	var after int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM rbac_audit_log`).Scan(&after))
	require.Equal(t, auditCount, after, "migrations must not fabricate runtime audit entries")
	var version int32
	require.NoError(t, conn.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&version))
	require.Equal(t, int32(len(m.Migrations)), version)

	// Exercise first adoption of existing groups after upgrade. This callback
	// is a DB fixture; public authority checks are covered by server tests.
	d.SetRBACAuditChain(chain)
	view.Source.Spec.(configuration.GroupsSpec).Groups[0].Name = "Reviewed after upgrade"
	source, err := json.Marshal(view.Source)
	require.NoError(t, err)
	author := ConfigurationActor{UserID: authorID, ExternalID: "did:upgrade:" + authorID, PrincipalKind: "human"}
	reviewer := ConfigurationActor{UserID: reviewerID, ExternalID: "did:upgrade:" + reviewerID, PrincipalKind: "human"}
	draft, err := d.SubmitConfigurationRevision(ctx, source, author)
	require.NoError(t, err)
	_, err = d.ActivateConfigurationRevisions(ctx, view.Source.Scope, []string{draft.ID}, reviewer, func(context.Context, *Tx, ConfigurationActivation) error { return nil })
	require.NoError(t, err)
	afterAdoption := snapshot()
	for _, table := range []string{"contracts", "contract_grants", "users", "user_memberships", "eth_address_links", "refresh_tokens", "revoked_tokens"} {
		require.Equal(t, before[table], afterAdoption[table], "configuration adoption must not replay operational state: %s", table)
	}

	// Check the retained projection barrier as the actual restricted runtime
	// role, rather than relying on the HTTP setter's managed-state check.
	exec(`SET ROLE privacy_proxy_app`)
	_, err = conn.Exec(ctx, `UPDATE group_access SET allowed_methods=ARRAY['eth_getBalance'] WHERE group_id=$1`, group)
	require.ErrorContains(t, err, "configuration revision")
	exec(`RESET ROLE`)
	_, err = conn.Exec(ctx, `UPDATE configuration_revisions SET source='{}' WHERE id=$1`, draft.ID)
	require.ErrorContains(t, err, "immutable")

	require.NoError(t, d.Close())
	reopened, err := New(dsn)
	require.NoError(t, err)
	defer reopened.Close()
	selected, err := reopened.GetConfigurationContext(ctx, view.Source.Scope, configuration.Groups)
	require.NoError(t, err)
	require.NotNil(t, selected.Active)
	require.Equal(t, draft.ID, selected.Active.ID)
	require.Equal(t, draft.Digest, selected.Active.Digest)
	require.Equal(t, reviewerID, *selected.Active.ActivatedBy)
	require.Equal(t, afterAdoption, snapshot(), "reopening must recover the selected state without rewriting facts or history")
	verified, err := audit.NewVerifier(reopened.Conn(), reopened).Verify(ctx, audit.ChainRBACAuditLog)
	require.NoError(t, err)
	require.True(t, verified.OK, "upgrade and adoption must preserve the audit chain: %s", verified.FirstMismatchReason)
}
