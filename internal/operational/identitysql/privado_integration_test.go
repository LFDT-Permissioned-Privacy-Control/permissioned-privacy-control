package identitysql_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	f "privacy-proxy/internal/brokertest"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identitybroker/privado"
	"privacy-proxy/internal/operational/identitysql"
)

// These are SQL protocol/ACL fixtures only. Synthetic ciphertext is NEVER
// accepted as identity evidence by a Service or Provider.
func storeChallenge(x *fixture) b.PrivadoChallengeRecord {
	return b.PrivadoChallengeRecord{ID: uuid.NewString(), Scope: x.scope, ProfileID: "role", ProfileDigest: b.Hash("public-test-profile").String(), Recipient: b.RecipientBinding{1}, Mode: privado.Login, EncryptionKeyID: "test", Ciphertext: bytes.Repeat([]byte{4}, 28), CreatedAt: x.clock().Truncate(time.Second), ExpiresAt: x.clock().Truncate(time.Second).Add(5 * time.Minute)}
}
func storeOffer(t *testing.T, p b.PrivadoChallengeRecord) b.PrivadoOfferRecord {
	d := b.Hash("public-test-digest").String()
	return b.PrivadoOfferRecord{RequestID: p.ID, Scope: p.Scope, ContextDigest: b.Hash("public-test-context"), ProofDigest: b.Hash("public-test-proof"), HolderDID: f.PublicFixtureDID(t, 77), ActorID: "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Network: "polygon:mumbai", ProfileID: p.ProfileID, ProfileDigest: p.ProfileDigest, SourceAuthDigest: d, Provider: privado.Metadata{IdentityDigest: d, ProfilePlanDigest: d, NetworkPlanDigest: d, DocumentPlanDigest: d}, ClaimsAsOf: p.CreatedAt.Unix(), NotAfter: p.ExpiresAt.Unix(), VerifiedAt: p.CreatedAt.Unix(), EncryptionKeyID: "test", Ciphertext: bytes.Repeat([]byte{5}, 28)}
}
func TestActualPrivadoStoreIsolationAndImmutableOffers(t *testing.T) {
	x := setup(t)
	proof, e := identitysql.OpenProofV2(t.Context(), x.proofDSN, x.scope, x.clock)
	if e != nil {
		t.Fatal(e)
	}
	defer proof.Close()
	if proof.Binding().Role != "public-proof" || x.one.Binding().Role != "private-app" {
		t.Fatal("wrong operational role")
	}
	for name, dsn := range map[string]string{"proof as private": x.proofDSN, "retention as private": x.retentionDSN} {
		t.Run(name, func(t *testing.T) {
			if s, e := identitysql.OpenPrivateV2(t.Context(), dsn, x.scope, x.clock); e == nil {
				s.Close()
				t.Fatal("wrong role accepted")
			}
		})
	}
	if s, e := identitysql.OpenProofV2(t.Context(), x.appDSN, x.scope, x.clock); e == nil {
		s.Close()
		t.Fatal("private role accepted as publicproof")
	}
	p := storeChallenge(x)
	if e = x.one.InsertPrivadoLoginChallenge(t.Context(), x.scope, p, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	saved, e := proof.ReadPrivadoChallenge(t.Context(), x.scope, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	offer := storeOffer(t, saved)
	var wg sync.WaitGroup
	results := make(chan b.PrivadoOfferCommit, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := proof.InstallPrivadoOffer(t.Context(), x.scope, saved, offer, func() error { return nil })
			results <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	inserted, existing := 0, 0
	for r := range results {
		if !r.Committed {
			t.Fatal("unknown offer commit")
		}
		if r.Kind == b.OfferInserted {
			inserted++
		}
		if r.Kind == b.OfferExisting && r.Existing != nil {
			existing++
		}
	}
	if inserted != 1 || existing != 1 {
		t.Fatal("offer mutation raced", inserted, existing)
	}
	flow, e := x.two.ReadPrivadoFlow(t.Context(), x.scope, p.ID, p.Recipient)
	if e != nil || flow.Offer == nil {
		t.Fatal("crosspool restore", e)
	}
	if _, e = x.two.ReadPrivadoFlow(t.Context(), x.scope, p.ID, b.RecipientBinding{2}); !errors.Is(e, b.ErrUnauthorized) {
		t.Fatal("foreign recipient read", e)
	}
	// Exact schema shape and effective privileges are checked before mounting.
	if _, e = x.owner.Exec(t.Context(), `GRANT UPDATE(mode) ON ops_identity_v2.privado_challenges TO broker_proof`); e != nil {
		t.Fatal(e)
	}
	if s, e := identitysql.OpenProofV2(t.Context(), x.proofDSN, x.scope, x.clock); e == nil {
		s.Close()
		t.Fatal("extra column grant accepted")
	}
	if e = identitysql.MigrateV2(t.Context(), x.ownerDSN, "broker_app", "broker_proof", "broker_retention", x.scope, true); e != nil {
		t.Fatal("offline role repair", e)
	}
	if _, e = x.owner.Exec(t.Context(), `GRANT EXECUTE ON FUNCTION ops_identity_v2.privado_immutable() TO broker_proof`); e != nil {
		t.Fatal(e)
	}
	if s, e := identitysql.OpenProofV2(t.Context(), x.proofDSN, x.scope, x.clock); e == nil {
		s.Close()
		t.Fatal("extra trigger-function grant accepted")
	}
	if e = identitysql.MigrateV2(t.Context(), x.ownerDSN, "broker_app", "broker_proof", "broker_retention", x.scope, true); e != nil {
		t.Fatal(e)
	}
	if _, e = x.owner.Exec(t.Context(), `GRANT SELECT ON ops_identity_v2.metadata TO PUBLIC`); e != nil {
		t.Fatal(e)
	}
	if s, e := identitysql.OpenPrivateV2(t.Context(), x.appDSN, x.scope, x.clock); e == nil {
		s.Close()
		t.Fatal("unexpected PUBLIC grant accepted")
	}
	if _, e = x.owner.Exec(t.Context(), `REVOKE SELECT ON ops_identity_v2.metadata FROM PUBLIC`); e != nil {
		t.Fatal(e)
	}
	for _, row := range []struct{ name, alter, repair string }{{"ENABLE RLS hides stored rows", "ENABLE ROW LEVEL SECURITY", "DISABLE ROW LEVEL SECURITY"}, {"FORCE RLS is altered shape", "FORCE ROW LEVEL SECURITY", "NO FORCE ROW LEVEL SECURITY"}} {
		t.Run(row.name, func(t *testing.T) {
			if _, e := x.owner.Exec(t.Context(), `ALTER TABLE ops_identity_v2.privado_challenges `+row.alter); e != nil {
				t.Fatal(e)
			}
			if row.alter == "ENABLE ROW LEVEL SECURITY" {
				var n int
				app, e := pgx.Connect(t.Context(), x.appDSN)
				if e != nil {
					t.Fatal(e)
				}
				e = app.QueryRow(t.Context(), `SELECT count(*) FROM ops_identity_v2.privado_challenges`).Scan(&n)
				_ = app.Close(t.Context())
				if e != nil || n != 0 {
					t.Fatal("actual default-deny RLS did not hide the stored challenge", n, e)
				}
			}
			if s, e := identitysql.OpenPrivateV2(t.Context(), x.appDSN, x.scope, x.clock); e == nil {
				s.Close()
				t.Fatal("altered RLS shape accepted at startup")
			}
			if _, e := x.owner.Exec(t.Context(), `ALTER TABLE ops_identity_v2.privado_challenges `+row.repair); e != nil {
				t.Fatal(e)
			}
			if s, e := identitysql.OpenPrivateV2(t.Context(), x.appDSN, x.scope, x.clock); e != nil {
				t.Fatal("repaired no-RLS shape rejected", e)
			} else {
				s.Close()
			}
		})
	}
	if _, e = x.owner.Exec(t.Context(), `ALTER TABLE ops_identity_v2.privado_offers DROP CONSTRAINT offer_challenge_fk`); e != nil {
		t.Fatal(e)
	}
	if s, e := identitysql.OpenPrivateV2(t.Context(), x.appDSN, x.scope, x.clock); e == nil {
		s.Close()
		t.Fatal("missing foreign key accepted")
	}
}
func TestActualPrivadoFinalGateAndOneUseRollback(t *testing.T) {
	x := setup(t)
	proof, e := identitysql.OpenProofV2(t.Context(), x.proofDSN, x.scope, x.clock)
	if e != nil {
		t.Fatal(e)
	}
	defer proof.Close()
	p := storeChallenge(x)
	gate := func() error { return nil }
	if e = x.one.InsertPrivadoLoginChallenge(t.Context(), x.scope, p, gate); e != nil {
		t.Fatal(e)
	}
	p, e = proof.ReadPrivadoChallenge(t.Context(), x.scope, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	offer := storeOffer(t, p)
	if _, e = proof.InstallPrivadoOffer(t.Context(), x.scope, p, offer, gate); e != nil {
		t.Fatal(e)
	}
	snapshot, e := x.one.ReadPrivadoFlow(t.Context(), x.scope, p.ID, p.Recipient)
	if e != nil {
		t.Fatal(e)
	}
	family := b.Family{Provider: b.FamilyPrivado, ID: uuid.NewString(), RequestID: p.ID, Scope: x.scope, Actor: offer.ActorID, ProfileID: p.ProfileID, ProfileDigest: p.ProfileDigest, Authority: "privado", Subject: offer.HolderDID, Kind: "human", Recipient: p.Recipient, Generation: 0, CurrentHandleHash: b.Hash("public-synthetic-handle"), EncryptionKeyID: "test", Ciphertext: bytes.Repeat([]byte{6}, 28), CreatedAt: x.clock(), AbsoluteExpiresAt: x.clock().Add(b.FamilyLifetime), LastRotatedAt: x.clock()}
	prepared := b.PrivadoCompletion{Kind: b.Create, Family: family}
	n := 0
	_, e = x.one.CompletePrivadoFlow(t.Context(), x.scope, snapshot, prepared, func() error {
		n++
		if n >= 2 {
			return b.ErrUnauthorized
		}
		return nil
	})
	if e == nil {
		t.Fatal("final gate not checked")
	}
	var count int
	if e = x.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_identity_v2.renewal_families WHERE family_id=$1::uuid`, family.ID).Scan(&count); e != nil || count != 0 {
		t.Fatal("family commit escaped failed gate", count, e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*identitysql.Store{x.one, x.two} {
		wg.Add(1)
		go func(store *identitysql.Store) {
			defer wg.Done()
			c, e := store.CompletePrivadoFlow(t.Context(), x.scope, snapshot, prepared, gate)
			if e == nil && (!c.Committed || c.Kind != b.Create) {
				e = b.ErrUnavailable
			}
			results <- e
		}(store)
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, b.ErrUnauthorized) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal("completion not one-use", success)
	}
	if _, e = proof.ReadPrivadoChallenge(t.Context(), x.scope, p.ID); !errors.Is(e, b.ErrUnauthorized) {
		t.Fatal("completed challenge persisted", e)
	}
	if _, e = x.one.ReadPrivadoFamily(t.Context(), x.scope, family.ID); e != nil {
		t.Fatal(e)
	}
	called := false
	if _, e = x.one.WithFamily(t.Context(), x.scope, family.ID, func(b.Family) (b.FamilyDecision, error) {
		called = true
		return b.FamilyDecision{Kind: b.DenyUnchanged}, nil
	}, nil); e == nil || called {
		t.Fatal("legacy Azure path dispatched a Privado family", e)
	}
	old, e := x.one.ReadPrivadoFamily(t.Context(), x.scope, family.ID)
	if e != nil {
		t.Fatal(e)
	}
	capture := b.PrivadoHandleCapture{FamilyID: old.ID, ActorID: old.Actor, ProfileID: old.ProfileID, ProfileDigest: old.ProfileDigest, Generation: old.Generation, HandleHash: old.CurrentHandleHash, Recipient: old.Recipient, AbsoluteExpiresUnix: old.AbsoluteExpiresAt.Unix(), Scope: x.scope}
	renew := storeChallenge(x)
	renew.Mode = privado.Renew
	renew.ExpectedActorID = old.Actor
	renew.FamilyID = old.ID
	gen, hash := old.Generation, old.CurrentHandleHash
	renew.CurrentGeneration = &gen
	renew.CurrentHandleHash = &hash
	begin, e := x.one.BeginPrivadoRenewChallenge(t.Context(), x.scope, capture, old, renew, gate)
	if e != nil || !begin.Committed || begin.Kind != b.ChallengeInserted {
		t.Fatal("begin samefamily renewal", begin, e)
	}
	renew, e = proof.ReadPrivadoChallenge(t.Context(), x.scope, renew.ID)
	if e != nil {
		t.Fatal(e)
	}
	renewOffer := storeOffer(t, renew)
	if _, e = proof.InstallPrivadoOffer(t.Context(), x.scope, renew, renewOffer, gate); e != nil {
		t.Fatal(e)
	}
	renewSnapshot, e := x.one.ReadPrivadoFlow(t.Context(), x.scope, renew.ID, renew.Recipient)
	if e != nil {
		t.Fatal(e)
	}
	next := old
	next.Generation++
	next.CurrentHandleHash = b.Hash("next-public-synthetic-handle")
	next.Ciphertext = bytes.Repeat([]byte{8}, 28)
	rotation := b.PrivadoCompletion{Kind: b.Rotate, Family: next, Capture: &capture}
	if commit, e := x.one.CompletePrivadoFlow(t.Context(), x.scope, renewSnapshot, rotation, gate); e != nil || !commit.Committed || commit.Kind != b.Rotate {
		t.Fatal("samefamily rotation", commit, e)
	}
	// A late completion is public-flow replay, not authenticated renewal-handle
	// replay. It must deny without revoking the rotated family.
	if _, e = x.two.CompletePrivadoFlow(t.Context(), x.scope, renewSnapshot, rotation, gate); !errors.Is(e, b.ErrUnauthorized) {
		t.Fatal("late completion", e)
	}
	current, e := x.one.ReadPrivadoFamily(t.Context(), x.scope, family.ID)
	if e != nil || current.Generation != 1 || current.RevokedAt != nil {
		t.Fatal("late proof revoked family", current.Generation, e)
	}
	renew.ID = uuid.NewString()
	begin, e = x.two.BeginPrivadoRenewChallenge(t.Context(), x.scope, capture, old, renew, gate)
	if e != nil || !begin.Committed || begin.Kind != b.ChallengeRevokeDeny {
		t.Fatal("authentic stale handle did not commit revoke", begin, e)
	}
	current, e = x.one.ReadPrivadoFamily(t.Context(), x.scope, family.ID)
	if e != nil || current.RevokedAt == nil {
		t.Fatal("stale handle revoke absent", e)
	}
}
