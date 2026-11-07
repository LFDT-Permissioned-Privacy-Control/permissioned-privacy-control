package admissionsql_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
)

// These fixtures exercise the real SQL journal/restore contract. They are not
// native approvals, included-chain evidence, or an ownership-serving API.
func creationScope(t *testing.T, d *database) (a.NetworkBinding, a.Scope) {
	t.Helper()
	binding := a.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: common.HexToHash("0x01").Hex(), DeploymentID: uuid.NewString()}
	s := a.Scope{State: a.ExpectedState{Generation: uuid.NewString(), Coverage: admissionsql.EmptyCoverage()}, Organization: f.Org, Actor: f.Actor(f.Subject), Hash: common.HexToHash("0x01")}
	s.Network, _ = binding.Key()
	if err := admissionsql.BootstrapEmpty(t.Context(), d.ownerDSN, binding, s.State.Generation); err != nil {
		t.Fatal(err)
	}
	return binding, s
}

func creationIntent(t *testing.T, scope a.Scope) a.CreationIntent {
	t.Helper()
	creator := common.HexToAddress("0x1111111111111111111111111111111111111111")
	p := nativeadmission.CreationPlanData{Version: nativeadmission.CreationPlanVersion, Hash: scope.Hash, RootOrg: scope.Organization,
		Manifest: a.HashParts("fixture-manifest-1").String(), Runtime: a.HashParts("fixture-runtime-1").String(), Chain: "1", Evidence: rpcexecution.LifecycleSignedProfileID,
		Entries:      []nativeadmission.CreationEntry{{Address: common.HexToAddress("0x2222222222222222222222222222222222222222"), Creator: creator, Kind: "CREATE", Namespace: scope.Organization, InputHash: crypto.Keccak256Hash([]byte{0x60, 1}), Value: "0x0", Caller: creator, Depth: 1, Record: 1, CreationParent: -1, FactoryRoot: 0}},
		Declarations: []policybundle.FactoryAttribution{{Address: a.AddressString(creator), OrganizationID: scope.Organization, CodeHash: crypto.Keccak256Hash([]byte{0x60, 0}).Hex(), Scope: policybundle.FactoryCreationSubtree}}, FactoryRoots: []nativeadmission.CreationFactoryRoot{{Entry: 0, Declaration: 0}}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	i := a.CreationIntent{Plan: raw, PlanDigest: a.Digest(nativeadmission.CreationPlanDigest(raw)), Anchor: rpcexecution.Anchor{Hash: common.HexToHash("0x1234"), Number: 10, Timestamp: uint64(f.Now), ChainID: "1", OrganizationID: scope.Organization, Profile: p.Evidence}, Factory: true, CapturedAt: time.Unix(f.Now, 0).UTC()}
	if _, err := i.Validate(scope); err != nil {
		t.Fatal("SQL fixture shape", err)
	}
	return i
}

func creationWitness(i a.CreationIntent, version string) a.Witness {
	w := a.Witness{AnchorHash: i.Anchor.Hash, AnchorNumber: i.Anchor.Number, AnchorTimestamp: i.Anchor.Timestamp, EvidenceProfile: i.Anchor.Profile, WalletVersion: a.HashParts(version), DecisionAt: i.CapturedAt, WalletEvidenceAt: i.CapturedAt, ManifestDigest: a.HashParts("witness-original-manifest"), ComplianceDigest: a.HashParts("witness-original-compliance")}
	w.ID = w.Digest()
	return w
}

func commitCreation(ctx context.Context, store *admissionsql.Store, scope a.Scope, i a.CreationIntent, w *a.Witness) error {
	receipt, err := store.WithRawTransaction(ctx, scope, func(raw a.RawTx) (a.CommitKind, error) {
		if w != nil {
			if _, err := raw.PutOrigin(a.Origin{Network: scope.Network, Hash: scope.Hash, Actor: scope.Actor, Organization: scope.Organization, FirstAdmittedAt: i.CapturedAt, Primary: *w}); err != nil {
				return 0, err
			}
		}
		_, err := raw.(a.CreationRawTx).PutCreationIntent(i)
		return a.CommitAllow, err
	})
	if err == nil && (!receipt.Committed || receipt.Kind != a.CommitAllow) {
		return errors.New("SQL intent did not commit")
	}
	return err
}

func creationUsage(t *testing.T, d *database, network a.Digest) a.CreationLimits {
	t.Helper()
	var u a.CreationLimits
	if err := d.owner.QueryRow(t.Context(), `SELECT work_count,plan_count,plan_bytes,wallet_ref_count,factory_ref_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1`, network[:]).Scan(&u.Work, &u.Plans, &u.Bytes, &u.WalletRefs, &u.FactoryRefs); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestCreationIntentActualPostgresJournalRecoveryAndRoles(t *testing.T) {
	d := setup(t)
	oldBinding, oldScope := creationScope(t, d)
	oldIntent := creationIntent(t, oldScope)
	oldWitness := creationWitness(oldIntent, "before-schema-upgrade")
	if _, err := d.one.WithRawTransaction(t.Context(), oldScope, func(raw a.RawTx) (a.CommitKind, error) {
		_, err := raw.PutOrigin(a.Origin{Network: oldScope.Network, Hash: oldScope.Hash, Actor: oldScope.Actor, Organization: oldScope.Organization, FirstAdmittedAt: oldIntent.CapturedAt, Primary: oldWitness})
		return a.CommitAllow, err
	}); err != nil {
		t.Fatal("existing schema1 history", err)
	}
	if s, err := admissionsql.OpenCreationWriter(t.Context(), d.appDSN, a.DefaultCreationLimits()); err == nil || s != nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("creation writer accepted schema1")
	}
	// Existing pools are explicitly drained; a migration cannot stop an old pool.
	d.one.Close()
	d.two.Close()
	if err := admissionsql.MigrateCreationIntents(t.Context(), d.ownerDSN, "admission_app", "admission_reader", "admission_retention"); !errors.Is(err, a.ErrConflict) {
		t.Fatal("upgrade accepted a ready network", err)
	}
	oldScope.State.Generation = uuid.NewString()
	if err := admissionsql.BeginRecovery(t.Context(), d.ownerDSN, oldBinding, oldScope.State.Generation); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.MigrateCreationIntents(t.Context(), d.ownerDSN, "admission_app", "admission_reader", "admission_retention"); err != nil {
		t.Fatal(err)
	}
	if err := admissionsql.FinalizeRecovery(t.Context(), d.ownerDSN, oldBinding, oldScope.State, true); err != nil {
		t.Fatal("existing history did not survive offline1->2", err)
	}
	one, err := admissionsql.OpenCreationWriter(t.Context(), d.appDSN, a.DefaultCreationLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(one.Close)
	two, err := admissionsql.OpenCreationWriter(t.Context(), d.appDSN, a.DefaultCreationLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(two.Close)
	if _, err := one.WithRawTransaction(t.Context(), oldScope, func(raw a.RawTx) (a.CommitKind, error) {
		origin, found, err := raw.GetOrigin()
		if err == nil && (!found || origin.Actor != oldScope.Actor || !origin.Primary.StableEqual(oldWitness) || origin.Primary.ManifestDigest != oldWitness.ManifestDigest) {
			return 0, errors.New("schema upgrade changed original history")
		}
		return a.CommitAllow, err
	}); err != nil || creationUsage(t, d, oldScope.Network) != (a.CreationLimits{}) {
		t.Fatal("schema2 manufactured intent for old history", err)
	}
	if info, err := admissionsql.InstalledSchema(t.Context(), d.ownerDSN); err != nil || info.Version != 2 || info.SourceChecksum != admissionsql.CreationSchemaChecksum() {
		t.Fatal("actual installed schema", info, err)
	}
	t.Run("factory branch saturation reserves wallet branch and duplicate is free", func(t *testing.T) {
		_, scope := creationScope(t, d)
		i := creationIntent(t, scope)
		for j := 0; j < a.MaxCreationRefsPerBranch; j++ {
			i.Anchor.Hash = common.BigToHash(big.NewInt(int64(100 + j)))
			if err := commitCreation(t.Context(), one, scope, i, nil); err != nil {
				t.Fatal(j, err)
			}
		}
		before := creationUsage(t, d, scope.Network)
		if err := commitCreation(t.Context(), two, scope, i, nil); err != nil || creationUsage(t, d, scope.Network) != before {
			t.Fatal("saturated duplicate changed counters", err)
		}
		i.Anchor.Hash = common.HexToHash("0x999")
		if err := commitCreation(t.Context(), two, scope, i, nil); !errors.Is(err, a.ErrConflict) || creationUsage(t, d, scope.Network) != before {
			t.Fatal("ninth factory ref was not atomic", err)
		}
		i.Factory = false
		for j := 0; j < a.MaxCreationRefsPerBranch; j++ {
			w := creationWitness(i, "wallet-"+big.NewInt(int64(j)).String())
			i.Wallet = &a.CreationWalletAuthority{Actor: scope.Actor, Organization: scope.Organization, Witness: w.ID}
			if err := commitCreation(t.Context(), one, scope, i, &w); err != nil {
				t.Fatal("factory exhaustion blocked reserved wallet branch", j, err)
			}
		}
		before = creationUsage(t, d, scope.Network)
		w := creationWitness(i, "ninth-wallet")
		i.Wallet = &a.CreationWalletAuthority{Actor: scope.Actor, Organization: scope.Organization, Witness: w.ID}
		if err := commitCreation(t.Context(), two, scope, i, &w); !errors.Is(err, a.ErrConflict) || creationUsage(t, d, scope.Network) != before {
			t.Fatal("ninth wallet ref was not atomic", err)
		}
		var witnesses, generation int
		if err := d.owner.QueryRow(t.Context(), `SELECT (SELECT count(*)FROM ops_admission_v2.extra_privacy_witnesses WHERE network_key=$1),(SELECT generation FROM ops_admission_v2.creation_work WHERE network_key=$1)`, scope.Network[:]).Scan(&witnesses, &generation); err != nil || witnesses != 7 || generation != 16 {
			t.Fatal("rolled-back witness or incorrect generation", witnesses, generation, err)
		}
	})
	t.Run("M1 primary and extra witnesses stay immutable under current M2 plan", func(t *testing.T) {
		binding, scope := creationScope(t, d)
		i := creationIntent(t, scope)
		i.Factory = false
		for _, version := range []string{"primary", "extra"} {
			w := creationWitness(i, version)
			i.Wallet = &a.CreationWalletAuthority{Actor: scope.Actor, Organization: scope.Organization, Witness: w.ID}
			if err := commitCreation(t.Context(), one, scope, i, &w); err != nil {
				t.Fatal(err)
			}
		}
		p, _ := i.PlanData()
		p.Manifest = a.HashParts("current-manifest-M2").String()
		i.Plan, _ = json.Marshal(p)
		i.PlanDigest = a.Digest(nativeadmission.CreationPlanDigest(i.Plan))
		for _, version := range []string{"primary", "extra"} {
			w := creationWitness(i, version)
			w.ManifestDigest = a.HashParts("must-not-overwrite-M1")
			w.DecisionAt = w.DecisionAt.Add(time.Second)
			w.WalletEvidenceAt = w.WalletEvidenceAt.Add(time.Second)
			i.Wallet = &a.CreationWalletAuthority{Actor: scope.Actor, Organization: scope.Organization, Witness: w.ID}
			if err := commitCreation(t.Context(), two, scope, i, &w); err != nil {
				t.Fatal("M2 must retain actual M1 witness", err)
			}
			before := creationUsage(t, d, scope.Network)
			i.CapturedAt = i.CapturedAt.Add(time.Second)
			if err := commitCreation(t.Context(), one, scope, i, &w); err != nil || creationUsage(t, d, scope.Network) != before {
				t.Fatal("clock-only change consumed branch/capacity", err)
			}
			_, err := one.WithRawTransaction(t.Context(), scope, func(raw a.RawTx) (a.CommitKind, error) {
				stored, found, err := raw.(a.CreationRawTx).GetWitness(w.ID)
				if err == nil && (!found || stored.ManifestDigest != a.HashParts("witness-original-manifest") || !stored.DecisionAt.Equal(time.Unix(f.Now, 0))) {
					return 0, errors.New("original witness provenance was replaced")
				}
				return a.CommitAllow, err
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		usage := creationUsage(t, d, scope.Network)
		if usage.Plans != 2 || usage.WalletRefs != 4 || usage.FactoryRefs != 0 {
			t.Fatal("source/witness identities not independent", usage)
		}
		generation := uuid.NewString()
		if err := admissionsql.BeginRecovery(t.Context(), d.ownerDSN, binding, generation); err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.ownerDSN, binding, a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}, true); err != nil {
			t.Fatal("restore rejected legitimately separate M1/M2 provenance", err)
		}
	})
	t.Run("different hash two-pool aggregate cap race rolls back prior origin", func(t *testing.T) {
		_, scope := creationScope(t, d)
		limits := a.DefaultCreationLimits()
		limits.Work = 1
		first, err := admissionsql.OpenCreationWriter(t.Context(), d.appDSN, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		second, err := admissionsql.OpenCreationWriter(t.Context(), d.appDSN, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		ready, start := make(chan struct{}, 2), make(chan struct{})
		results := make(chan error, 2)
		for j, store := range []*admissionsql.Store{first, second} {
			s := scope
			s.Hash = common.BigToHash(big.NewInt(int64(j + 1)))
			i := creationIntent(t, s)
			w := creationWitness(i, "raced-wallet")
			i.Wallet = &a.CreationWalletAuthority{Actor: s.Actor, Organization: s.Organization, Witness: w.ID}
			go func() {
				_, err := store.WithRawTransaction(t.Context(), s, func(raw a.RawTx) (a.CommitKind, error) {
					if _, err := raw.PutOrigin(a.Origin{Network: s.Network, Hash: s.Hash, Actor: s.Actor, Organization: s.Organization, FirstAdmittedAt: i.CapturedAt, Primary: w}); err != nil {
						return 0, err
					}
					ready <- struct{}{}
					select {
					case <-start:
					case <-t.Context().Done():
						return 0, t.Context().Err()
					}
					_, err := raw.(a.CreationRawTx).PutCreationIntent(i)
					return a.CommitAllow, err
				})
				results <- err
			}()
		}
		for range 2 {
			select {
			case <-ready:
			case err := <-results:
				t.Fatal("race did not reach both independently locked hashes", err)
			case <-time.After(3 * time.Second):
				t.Fatal("race barrier deadline")
			}
		}
		close(start)
		allowed, unavailable := 0, 0
		for range 2 {
			err := <-results
			if err == nil {
				allowed++
			} else if errors.Is(err, a.ErrUnavailable) {
				unavailable++
			} else {
				t.Fatal("unexpected cap outcome", err)
			}
		}
		var origins int
		if err := d.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1`, scope.Network[:]).Scan(&origins); err != nil || allowed != 1 || unavailable != 1 || origins != 1 || creationUsage(t, d, scope.Network).Work != 1 {
			t.Fatal("aggregate cap or all-effects rollback failed", allowed, unavailable, origins, err)
		}
	})
	t.Run("paged restore validates last page and fails unready on corruption", func(t *testing.T) {
		binding, scope := creationScope(t, d)
		var last a.CreationIntent
		for j := 1; j <= 257; j++ {
			scope.Hash = common.BigToHash(big.NewInt(int64(j)))
			last = creationIntent(t, scope)
			if err := commitCreation(t.Context(), one, scope, last, nil); err != nil {
				t.Fatal(j, err)
			}
		}
		if err := admissionsql.BeginRecovery(t.Context(), d.ownerDSN, binding, uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		var generation string
		if err := d.owner.QueryRow(t.Context(), `SELECT generation::text FROM ops_admission_v2.network_state WHERE network_key=$1`, scope.Network[:]).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		state := a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}
		execSQL := func(query string, args ...any) {
			t.Helper()
			if _, err := d.owner.Exec(t.Context(), query, args...); err != nil {
				t.Fatal(err)
			}
		}
		assertUnready := func() {
			t.Helper()
			var ready bool
			if err := d.owner.QueryRow(t.Context(), `SELECT ready FROM ops_admission_v2.network_state WHERE network_key=$1`, scope.Network[:]).Scan(&ready); err != nil || ready {
				t.Fatal("failed restore published readiness", ready, err)
			}
		}
		for _, timeout := range []time.Duration{0, -1, admissionsql.MaxRecoveryTimeout + 1} {
			if err := admissionsql.FinalizeRecoveryWithTimeout(t.Context(), d.ownerDSN, binding, state, true, timeout); !errors.Is(err, a.ErrInvalid) {
				t.Fatal("invalid offline timeout accepted", timeout, err)
			}
		}
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		if err := admissionsql.FinalizeRecoveryWithTimeout(cancelled, d.ownerDSN, binding, state, true, time.Minute); err == nil {
			t.Fatal("parent cancellation ignored")
		}
		assertUnready()
		for _, fault := range []struct {
			name, damage, repair string
			args                 []any
		}{
			{"last-page payload", `UPDATE ops_admission_v2.creation_plans SET payload=set_byte(payload,0,33)WHERE network_key=$1 AND tx_hash=$2`, `UPDATE ops_admission_v2.creation_plans SET payload=$3 WHERE network_key=$1 AND tx_hash=$2`, []any{scope.Network[:], scope.Hash[:], last.Plan}},
			{"last-page branch gap", `UPDATE ops_admission_v2.creation_authority_refs SET branch=2 WHERE network_key=$1 AND tx_hash=$2`, `UPDATE ops_admission_v2.creation_authority_refs SET branch=1 WHERE network_key=$1 AND tx_hash=$2`, []any{scope.Network[:], scope.Hash[:]}},
			{"last-page generation", `UPDATE ops_admission_v2.creation_work SET generation=2 WHERE network_key=$1 AND tx_hash=$2`, `UPDATE ops_admission_v2.creation_work SET generation=1 WHERE network_key=$1 AND tx_hash=$2`, []any{scope.Network[:], scope.Hash[:]}},
			{"capacity", `UPDATE ops_admission_v2.creation_capacity SET plan_bytes=plan_bytes+1 WHERE network_key=$1`, `UPDATE ops_admission_v2.creation_capacity SET plan_bytes=plan_bytes-1 WHERE network_key=$1`, []any{scope.Network[:]}},
			{"work infinite timestamp", `UPDATE ops_admission_v2.creation_work SET updated_at='infinity' WHERE network_key=$1 AND tx_hash=$2`, `UPDATE ops_admission_v2.creation_work SET updated_at=created_at WHERE network_key=$1 AND tx_hash=$2`, []any{scope.Network[:], scope.Hash[:]}},
		} {
			t.Run(fault.name, func(t *testing.T) {
				// Some repairs need a payload parameter not used by the damage.
				damageArgs := fault.args
				if len(damageArgs) == 3 {
					damageArgs = damageArgs[:2]
				}
				execSQL(fault.damage, damageArgs...)
				if err := admissionsql.FinalizeRecoveryWithTimeout(t.Context(), d.ownerDSN, binding, state, true, time.Minute); !errors.Is(err, a.ErrCoverage) {
					t.Fatal("corrupt restore was accepted", err)
				}
				assertUnready()
				execSQL(fault.repair, fault.args...)
			})
		}
		t.Run("coherent cross-chain plan and seed", func(t *testing.T) {
			other := last
			p, err := other.PlanData()
			if err != nil {
				t.Fatal(err)
			}
			p.Chain, other.Anchor.ChainID = "2", "2"
			other.Plan, _ = json.Marshal(p)
			other.PlanDigest = a.Digest(nativeadmission.CreationPlanDigest(other.Plan))
			// Shape, payload digest, metadata, seed, FK and byte counters all
			// remain coherent. Only the network's verified chain is different.
			replace := func(from, to a.CreationIntent, chain string) {
				t.Helper()
				tx, err := d.owner.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(t.Context())
				seed := to.SeedDigest("FACTORY")
				statements := []struct {
					sql  string
					args []any
				}{
					{`INSERT INTO ops_admission_v2.creation_plans SELECT network_key,tx_hash,$3,version,$4,entry_count,root_org,manifest_digest,runtime_digest,$5,evidence_profile,created_at FROM ops_admission_v2.creation_plans WHERE network_key=$1 AND tx_hash=$2 AND plan_digest=$6`, []any{scope.Network[:], scope.Hash[:], to.PlanDigest[:], to.Plan, chain, from.PlanDigest[:]}},
					{`UPDATE ops_admission_v2.creation_authority_refs SET plan_digest=$3,seed_digest=$4 WHERE network_key=$1 AND tx_hash=$2`, []any{scope.Network[:], scope.Hash[:], to.PlanDigest[:], seed[:]}},
					{`DELETE FROM ops_admission_v2.creation_plans WHERE network_key=$1 AND tx_hash=$2 AND plan_digest=$3`, []any{scope.Network[:], scope.Hash[:], from.PlanDigest[:]}},
					{`UPDATE ops_admission_v2.creation_capacity SET plan_bytes=plan_bytes+$2 WHERE network_key=$1`, []any{scope.Network[:], len(to.Plan) - len(from.Plan)}},
				}
				for _, statement := range statements {
					if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
						t.Fatal(err)
					}
				}
				if err := tx.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			replace(last, other, "2")
			if err := admissionsql.FinalizeRecoveryWithTimeout(t.Context(), d.ownerDSN, binding, state, true, time.Minute); !errors.Is(err, a.ErrCoverage) {
				t.Fatal("cross-chain restore passed coherent local metadata", err)
			}
			assertUnready()
			replace(other, last, "1")
		})
		// An earlier parent deadline also bounds waiting for the offline lock.
		lock, err := pgx.Connect(t.Context(), d.ownerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close(context.Background())
		if _, err := lock.Exec(t.Context(), `SELECT pg_advisory_lock(49222381407003)`); err != nil {
			t.Fatal(err)
		}
		short, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
		started := time.Now()
		err = admissionsql.FinalizeRecoveryWithTimeout(short, d.ownerDSN, binding, state, true, time.Minute)
		stop()
		if err == nil || time.Since(started) > time.Second {
			t.Fatal("earlier parent deadline ignored", err)
		}
		if _, err := lock.Exec(t.Context(), `SELECT pg_advisory_unlock(49222381407003)`); err != nil {
			t.Fatal(err)
		}
		assertUnready()
		if err := admissionsql.FinalizeRecoveryWithTimeout(t.Context(), d.ownerDSN, binding, state, false, time.Minute); !errors.Is(err, a.ErrInvalid) {
			t.Fatal("missing operator attestation accepted", err)
		}
		if err := admissionsql.FinalizeRecoveryWithTimeout(t.Context(), d.ownerDSN, binding, state, true, time.Minute); err != nil {
			t.Fatal("valid multi-page restore", err)
		}
	})
	t.Run("application cannot rewrite authority and reader retention remain narrow", func(t *testing.T) {
		for _, role := range []struct {
			dsn     string
			queries []string
		}{
			{d.appDSN, []string{`UPDATE ops_admission_v2.creation_plans SET payload=payload`, `UPDATE ops_admission_v2.creation_authority_refs SET captured_at=captured_at`, `DELETE FROM ops_admission_v2.creation_authority_refs`, `TRUNCATE ops_admission_v2.creation_work`, `SELECT * FROM public.users`}},
			{d.readerDSN, []string{`DELETE FROM ops_admission_v2.creation_work`, `UPDATE ops_admission_v2.creation_work SET generation=generation+1`}},
			{d.retentionDSN, []string{`SELECT * FROM ops_admission_v2.creation_plans`, `DELETE FROM ops_admission_v2.creation_work`}},
		} {
			conn, err := pgx.Connect(t.Context(), role.dsn)
			if err != nil {
				t.Fatal(err)
			}
			for _, query := range role.queries {
				_, err := conn.Exec(t.Context(), query)
				var pgerr interface{ SQLState() string }
				if err == nil || !errors.As(err, &pgerr) || pgerr.SQLState() != "42501" {
					t.Fatal("unexpected permission result", query, err)
				}
			}
			conn.Close(t.Context())
		}
		// Existing profiles can still open exact2 with their unchanged role.
		r, err := admissionsql.OpenReader(t.Context(), d.readerDSN)
		if err != nil {
			t.Fatal("old-profile reader on exact2", err)
		}
		r.Close()
	})
	t.Run("startup rejects altered new-table nullability and default", func(t *testing.T) {
		for _, fault := range []struct{ damage, repair string }{
			{`ALTER TABLE ops_admission_v2.creation_work ALTER COLUMN created_at DROP NOT NULL`, `ALTER TABLE ops_admission_v2.creation_work ALTER COLUMN created_at SET NOT NULL`},
			{`ALTER TABLE ops_admission_v2.creation_capacity ALTER COLUMN work_count SET DEFAULT 1`, `ALTER TABLE ops_admission_v2.creation_capacity ALTER COLUMN work_count SET DEFAULT 0`},
		} {
			if _, err := d.owner.Exec(t.Context(), fault.damage); err != nil {
				t.Fatal(err)
			}
			s, err := admissionsql.OpenCreationWriter(t.Context(), d.appDSN, a.DefaultCreationLimits())
			if s != nil {
				s.Close()
			}
			if err == nil || s != nil {
				t.Fatal("altered schema accepted as exact schema2")
			}
			if _, err := d.owner.Exec(t.Context(), fault.repair); err != nil {
				t.Fatal(err)
			}
			s, err = admissionsql.OpenCreationWriter(t.Context(), d.appDSN, a.DefaultCreationLimits())
			if err != nil {
				t.Fatal("repaired exact schema rejected", err)
			}
			s.Close()
		}
	})
}
