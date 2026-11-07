package identitysql_test

import (
	"bytes"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/operational/identitysql"
)

func TestActualIdentitySchemaV2UpgradePreservesAzureContinuity(t *testing.T) {
	x := setup(t)
	recipient := b.RecipientBinding{42}
	service := x.service(t, x.one)
	login := x.login(t, service, recipient)
	_, handle := credentials(t, login)
	session, e := login.SessionInfo()
	if e != nil {
		t.Fatal(e)
	}
	old, e := x.one.ReadPrivadoFamily(t.Context(), x.scope, session.ID)
	if e != nil {
		t.Fatal(e)
	}
	// A separate, owned database receives the EXACT existing001 schema and one
	// actual Azure encrypted family+MAC from the unchanged legacy grant engine.
	if _, e = x.owner.Exec(t.Context(), `CREATE DATABASE broker_upgrade`); e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(x.ownerDSN)
	u.Path = "/broker_upgrade"
	ownerDSN := u.String()
	if e = identitysql.Migrate(t.Context(), ownerDSN, "broker_app", "broker_retention", x.scope); e != nil {
		t.Fatal("v1 preparation", e)
	}
	owner, e := pgx.Connect(t.Context(), ownerDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close(t.Context())
	_, e = owner.Exec(t.Context(), `INSERT INTO ops_identity_v2.renewal_families(family_id,originating_request_id,namespace,recovery_epoch,actor_id,profile_id,profile_digest,identity_authority,source_tenant,source_subject,principal_kind,oidc_subject_hash,login_nonce_hash,original_auth_time,recipient_hash,generation,current_handle_hash,encryption_key_id,refresh_ciphertext,created_at,absolute_expires_at,last_rotated_at,revoked_at)VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`, old.ID, old.RequestID, old.Scope.Namespace.String(), old.Scope.State.RecoveryEpoch, old.Actor, old.ProfileID, old.ProfileDigest, old.Authority, old.Tenant, old.Subject, string(old.Kind), old.OIDCSubjectHash[:], old.NonceHash[:], old.OriginalAuthTime, old.Recipient[:], old.Generation, old.CurrentHandleHash[:], old.EncryptionKeyID, old.Ciphertext, old.CreatedAt, old.AbsoluteExpiresAt, old.LastRotatedAt, old.RevokedAt)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.Exec(t.Context(), `UPDATE ops_identity_v2.metadata SET ready=true`); e != nil {
		t.Fatal(e)
	}
	u.User = url.UserPassword("broker_app", "broker-test-only")
	appDSN := u.String()
	if store, e := identitysql.Open(t.Context(), appDSN, x.scope, x.clock); e == nil {
		store.Close()
		t.Fatal("new binary accepted schema1")
	}
	if e = identitysql.MigrateV2(t.Context(), ownerDSN, "broker_app", "broker_proof", "broker_retention", x.scope, false); e == nil {
		t.Fatal("upgrade without drain attestation")
	}
	if e = identitysql.MigrateV2(t.Context(), ownerDSN, "broker_app", "broker_proof", "broker_retention", x.scope, true); e != nil {
		t.Fatal("additive v2 migration", e)
	}
	store, e := identitysql.Open(t.Context(), appDSN, x.scope, x.clock)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	retained, e := store.ReadPrivadoFamily(t.Context(), x.scope, old.ID)
	if e != nil || !bytes.Equal(retained.Ciphertext, old.Ciphertext) || retained.Scope != old.Scope || retained.Generation != old.Generation || retained.CurrentHandleHash != old.CurrentHandleHash || retained.OIDCSubjectHash != old.OIDCSubjectHash || retained.NonceHash != old.NonceHash || retained.Provider != b.FamilyAzure {
		t.Fatal("migration rewrote Azure cryptographic continuity", e)
	}
	if _, e = x.service(t, store).RenewAzure(t.Context(), handle, recipient); e != nil {
		t.Fatal("oldSourceV1/MAC/AAD renewal failed after schema2 upgrade", e)
	}
	if e = identitysql.Migrate(t.Context(), ownerDSN, "broker_app", "broker_retention", x.scope); e == nil {
		t.Fatal("legacy001 migrator claimed schema2 success")
	}
}
