package identitysql_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	f "privacy-proxy/internal/brokertest"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/operational/identitysql"
)

func TestActualPrivadoCapacityIncludesExpiredOldEpochUntilDeletion(t *testing.T) {
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
	// PUBLIC SYNTHETIC SQL-shape rows: not proofs and never passed to a
	// verifier.63 max-size old expired envelopes exhaust BYTES before COUNT.
	d := b.Hash("public-capacity").String()
	oldEpoch := uuid.NewString()
	oldTime := x.clock().Truncate(time.Second).Add(-200 * time.Second)
	expired := oldTime.Add(100 * time.Second)
	holder := f.PublicFixtureDID(t, 88)
	_, e = x.owner.Exec(t.Context(), `WITH added AS(INSERT INTO ops_identity_v2.privado_challenges(request_id,namespace,recovery_epoch,profile_id,profile_digest,recipient_hash,mode,encryption_key_id,context_ciphertext,created_at,expires_at)SELECT gen_random_uuid(),$1,$2::uuid,'role',$3,$4,'login','test',$5,$6,$7 FROM generate_series(1,63) RETURNING request_id) INSERT INTO ops_identity_v2.privado_offers(request_id,namespace,recovery_epoch,context_digest,proof_digest,holder_did,actor_id,network,profile_id,profile_digest,source_auth_digest,identity_digest,profile_plan_digest,network_plan_digest,document_plan_digest,claims_as_of,not_after,verified_at,encryption_key_id,proof_ciphertext)SELECT request_id,$1,$2::uuid,$4,$4,$8,'ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','polygon:mumbai','role',$3,$3,$3,$3,$3,$3,$9,$10,$9,'test',$11 FROM added`, x.scope.Namespace.String(), oldEpoch, d, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 28), oldTime, expired, holder, oldTime.Unix(), expired.Unix(), bytes.Repeat([]byte{3}, b.MaxPrivadoCipherBytes))
	if e != nil {
		t.Fatal(e)
	}
	offer.Ciphertext = bytes.Repeat([]byte{4}, b.MaxPrivadoCipherBytes)
	if _, e = proof.InstallPrivadoOffer(t.Context(), x.scope, p, offer, gate); !errors.Is(e, b.ErrConflict) {
		t.Fatal("expired oldepoch bytes ignored", e)
	}
	offer.Ciphertext = bytes.Repeat([]byte{4}, 28)
	if c, e := proof.InstallPrivadoOffer(t.Context(), x.scope, p, offer, gate); e != nil || !c.Committed || c.Kind != b.OfferInserted {
		t.Fatal("smaller64th envelope should fit both caps", c, e)
	}
	second := storeChallenge(x)
	if e = x.one.InsertPrivadoLoginChallenge(t.Context(), x.scope, second, gate); e != nil {
		t.Fatal(e)
	}
	second, e = proof.ReadPrivadoChallenge(t.Context(), x.scope, second.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = proof.InstallPrivadoOffer(t.Context(), x.scope, second, storeOffer(t, second), gate); !errors.Is(e, b.ErrConflict) {
		t.Fatal("64 old+current count ignored", e)
	}
	// Fill only small immutable contexts to the selected namespace bound. Old
	// epochs and expiry are not a capacity bypass until actual parent deletion.
	_, e = x.owner.Exec(t.Context(), `INSERT INTO ops_identity_v2.privado_challenges(request_id,namespace,recovery_epoch,profile_id,profile_digest,recipient_hash,mode,encryption_key_id,context_ciphertext,created_at,expires_at)SELECT gen_random_uuid(),$1,$2::uuid,'role',$3,$4,'login','test',$5,$6,$7 FROM generate_series(1,9935)`, x.scope.Namespace.String(), oldEpoch, d, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 28), oldTime.Add(10*time.Second), expired.Add(10*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if e = x.one.InsertPrivadoLoginChallenge(t.Context(), x.scope, storeChallenge(x), gate); !errors.Is(e, b.ErrConflict) {
		t.Fatal("expired oldepoch contexts ignored", e)
	}
	retention, e := identitysql.OpenRetentionV2(t.Context(), x.retentionDSN, x.scope, x.clock)
	if e != nil {
		t.Fatal(e)
	}
	defer retention.Close()
	counts, e := retention.CleanupOnce(t.Context(), 256)
	if e != nil || counts.PrivadoChallenges != 256 {
		t.Fatal("bounded parent retention", counts, e)
	}
	if e = x.one.InsertPrivadoLoginChallenge(t.Context(), x.scope, storeChallenge(x), gate); e != nil {
		t.Fatal("capacity did not recover after deletion", e)
	}
	if c, e := proof.InstallPrivadoOffer(t.Context(), x.scope, second, storeOffer(t, second), gate); e != nil || !c.Committed {
		t.Fatal("cascaded proof deletion did not restorecapacity", c, e)
	}
}
