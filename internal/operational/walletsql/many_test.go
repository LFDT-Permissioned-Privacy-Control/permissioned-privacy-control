package walletsql_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/disclosurewallet"
	"privacy-proxy/internal/operational/walletsql"
	w "privacy-proxy/internal/walletops"
)

func walletDataConfig(x *fixture, store w.MultiReader) disclosurewallet.Config {
	net, _ := (d.NetworkBinding{Environment: x.binding.Environment, ChainID: x.binding.ChainID, GenesisHash: x.binding.GenesisHash, DeploymentID: x.binding.DeploymentID}).Key()
	return disclosurewallet.Config{Store: store, Binding: x.binding, ExpectedState: x.state, Clock: func() time.Time { return time.Unix(x.clock.Load(), 0).UTC() }, Plan: d.SourcePlan{Version: 1, Profile: "ops.disclosure.data-sources/v1", BundleDigest: d.Digest(x.snapshot.Metadata().ManifestDigest), NetworkKey: d.Digest(walletsql.DigestString(net)), PlanDigest: d.Digest(walletsql.DigestString(sha256.Sum256([]byte("b0-test-common-source-plan")))), Resources: []p.Resource{p.AddressHistory, p.SanctionsReport, p.Transactions}}}
}
func walletDataScope(t *testing.T, c disclosurewallet.Config, targets []string, recipient string) d.ReadScope {
	t.Helper()
	n, err := d.Normalize(d.Query{Version: 1, Resource: p.AddressHistory, View: d.List}, p.Scope{TargetActors: targets, Resources: []p.Resource{p.AddressHistory}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 3600, End: f.Now + 3600}, Level: p.Full})
	if err != nil {
		t.Fatal(err)
	}
	return d.ReadScope{Namespace: d.Digest(walletsql.DigestString(sha256.Sum256([]byte("b0-test-case-namespace")))), CaseID: "22222222-2222-4222-8222-222222222222", CaseVersion: 1, RecipientActorID: recipient, DataOrganizationID: f.Org, BundleDigest: c.Plan.BundleDigest, RuleDigest: d.Digest(walletsql.DigestString(sha256.Sum256([]byte("b0-test-rule")))), EffectiveUntil: time.Unix(f.Now+300, 0).UTC(), Query: n}
}

func TestCurrentWalletMultiSnapshotActualPostgres(t *testing.T) {
	x := setup(t) // One owned cached PostgreSQL, reused by finite sequential subtests.
	store, err := walletsql.OpenReader(t.Context(), x.readerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c := walletDataConfig(x, store)
	reader, err := disclosurewallet.New(c)
	if err != nil {
		t.Fatal(err)
	}
	actorA, actorB := f.Actor(f.Subject), f.Actor(f.AdminSubject)
	actors := []string{actorA, actorB}
	sort.Strings(actors)
	scope := walletDataScope(t, c, []string{actorA}, actorB)

	t.Run("ready_empty_does_not_qualify_unknown_history", func(t *testing.T) {
		s, err := reader.Open(t.Context(), scope, nil)
		if err != nil || s.Wallets() == nil || len(s.Wallets()) != 0 {
			t.Fatal(err)
		}
		if _, err := d.SourceSetDigest([]d.SourceDescriptor{s.Descriptor()}, p.AddressHistory, d.List); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("wallet zero manufactured required historical coverage", err)
		}
		if err := s.CheckCurrent(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, state := range []w.ExpectedState{{Generation: uuid.NewString(), Coverage: x.state.Coverage}, {Generation: x.state.Generation, Coverage: sha256.Sum256([]byte("wrong coverage"))}} {
			if rows, err := store.LoadActiveMany(t.Context(), x.ns, state, actors); !errors.Is(err, w.ErrUnavailable) || rows != nil {
				t.Fatal("wrong state became empty", err)
			}
		}
		var missing w.Namespace
		missing[0] = 99
		if rows, err := store.LoadActiveMany(t.Context(), missing, x.state, actors); !errors.Is(err, w.ErrUnavailable) || rows != nil {
			t.Fatal("missing namespace became empty", err)
		}
		if _, err := x.owner.Exec(t.Context(), `UPDATE ops_wallet_v2.store_state SET ready=false WHERE namespace=$1`, x.ns[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("unready became empty", err)
		}
		if _, err := x.owner.Exec(t.Context(), `UPDATE ops_wallet_v2.store_state SET ready=true WHERE namespace=$1`, x.ns[:]); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("input_and_role_bounds", func(t *testing.T) {
		many := make([]string, 258)
		for i := range many {
			many[i] = f.Actor(uuid.NewString())
		}
		sort.Strings(many)
		for _, set := range [][]string{nil, many, {actorA, actorA}, {actors[1], actors[0]}, {"invalid"}} {
			if _, err := store.LoadActiveMany(t.Context(), x.ns, x.state, set); !errors.Is(err, w.ErrInvalid) {
				t.Fatal("invalid actor set", err)
			}
		}
		if _, err := x.store.LoadActiveMany(t.Context(), x.ns, x.state, actors); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("app mode accepted", err)
		}
		retention, err := walletsql.OpenRetention(t.Context(), x.retentionDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer retention.Close()
		if _, err := retention.LoadActiveMany(t.Context(), x.ns, x.state, actors); !errors.Is(err, w.ErrInvalid) {
			t.Fatal("retention mode accepted", err)
		}
		conn, err := pgx.Connect(t.Context(), x.readerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(context.Background())
		for _, sql := range []string{`SELECT message FROM ops_wallet_v2.wallet_links`, `SELECT signature FROM ops_wallet_v2.wallet_links`, `SELECT * FROM ops_wallet_v2.wallet_challenges`, `SELECT * FROM public.users`, `UPDATE ops_wallet_v2.wallet_links SET revoked=true,revoked_at=clock_timestamp()`, `DELETE FROM ops_wallet_v2.wallet_links`, `SELECT namespace FROM ops_wallet_v2.store_state FOR SHARE`} {
			_, err := conn.Exec(t.Context(), sql)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatal("reader privilege", sql, err)
			}
		}
	})

	shared := key(t)
	link(t, x, x.token, shared)
	link(t, x, x.otherToken, shared)
	t.Run("real_signed_shared_wallet_complete_tuple_set", func(t *testing.T) {
		s, err := reader.Open(t.Context(), scope, nil)
		if err != nil || len(s.Wallets()) != 2 {
			t.Fatal(err)
		}
		if s.Wallets()[0].Address != s.Wallets()[1].Address || s.Wallets()[0].ActorID == s.Wallets()[1].ActorID {
			t.Fatal("lost independent shared-wallet actor tuples", s.Wallets())
		}
		ref := d.SourceRef{Kind: d.WalletSource, ID: s.Descriptor().Reference}
		x.clock.Add(1)
		resumed, err := reader.Open(t.Context(), scope, &ref)
		if err != nil || resumed.Descriptor().Reference != ref.ID || !resumed.Descriptor().AsOf.After(s.Descriptor().AsOf) {
			t.Fatal("observation-only change broke resume", err)
		}
		// An unrelated actor's real signed link must not change this exact scope.
		otherToken := f.Token(t, x.snapshot, uuid.NewString())
		link(t, x, otherToken, key(t))
		if err := s.CheckCurrent(t.Context()); err != nil {
			t.Fatal("unselected actor invalidated scope", err)
		}
	})

	t.Run("uncommitted_unlink_is_atomic_then_commit_invalidates_sample", func(t *testing.T) {
		entered, resume := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			done <- x.store.WithActorTransaction(ctx, x.ns, x.state, actorA, func(tx w.ActorTx) error {
				if _, _, err := tx.Revoke(common.HexToAddress(address(shared)), time.Unix(x.clock.Load(), 0).UTC()); err != nil {
					return err
				}
				close(entered)
				select {
				case <-resume:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		select {
		case <-entered:
		case err := <-done:
			t.Fatal("unlink did not reach transaction barrier", err)
		case <-time.After(time.Second):
			t.Fatal("unlink barrier timeout")
		}
		s, err := reader.Open(t.Context(), scope, nil)
		if err != nil || len(s.Wallets()) != 2 {
			t.Fatal("uncommitted unlink leaked partial snapshot", err)
		}
		if err := s.CheckCurrent(t.Context()); err != nil {
			t.Fatal("MVCC read blocked on an uncommitted row update", err)
		}
		close(resume)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrConflict) {
			t.Fatal("committed unlink not observed", err)
		}
		if len(s.Wallets()) != 2 {
			t.Fatal("recheck mutated original sample")
		}
		ref := d.SourceRef{Kind: d.WalletSource, ID: s.Descriptor().Reference}
		if _, err := reader.Open(t.Context(), scope, &ref); !errors.Is(err, d.ErrConflict) {
			t.Fatal("stale current-link cursor resumed", err)
		}
	})

	t.Run("unlink_after_sampled_check_has_no_claimed_cross_store_fence", func(t *testing.T) {
		k := key(t)
		link(t, x, x.token, k)
		s, err := reader.Open(t.Context(), scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CheckCurrent(t.Context()); err != nil {
			t.Fatal(err)
		}
		before := s.Wallets()
		ref := s.Descriptor().Reference
		if status, _ := request(t, x.one, x.token, "DELETE", "/api/v2/eth/addresses/"+address(k), nil); status != 200 {
			t.Fatal(status)
		}
		if !slices.Equal(s.Wallets(), before) || s.Descriptor().Reference != ref {
			t.Fatal("late unlink rewrote sampled facts")
		}
		if err := s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrConflict) {
			t.Fatal("fresh later check did not see unlink", err)
		}
	})

	for _, table := range []string{"schema_version", "store_state", "wallet_links", "wallet_challenges"} {
		for _, flag := range []string{"ENABLE", "FORCE"} {
			t.Run(table+"_"+flag+"_rls_cold_and_live_denied", func(t *testing.T) {
				if _, err := x.owner.Exec(t.Context(), `ALTER TABLE ops_wallet_v2.`+table+` `+flag+` ROW LEVEL SECURITY`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := x.owner.Exec(t.Context(), `ALTER TABLE ops_wallet_v2.`+table+` DISABLE ROW LEVEL SECURITY;ALTER TABLE ops_wallet_v2.`+table+` NO FORCE ROW LEVEL SECURITY`); err != nil {
						t.Error(err)
					}
				}()
				if reopened, err := walletsql.OpenReader(t.Context(), x.readerDSN); !errors.Is(err, w.ErrUnavailable) {
					if reopened != nil {
						reopened.Close()
					}
					t.Fatal("unsupported shape accepted at startup", err)
				}
				if table == "store_state" || table == "wallet_links" {
					if _, err := reader.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrUnavailable) {
						t.Fatal("live RLS produced authoritative empty", err)
					}
				}
			})
			repaired, err := walletsql.OpenReader(t.Context(), x.readerDSN)
			if err != nil {
				t.Fatal("repaired startup", err)
			}
			repaired.Close()
			if _, err := reader.Open(t.Context(), scope, nil); err != nil {
				t.Fatal("repaired read", err)
			}
		}
	}

	t.Run("two_second_query_deadline_and_pool_recovery", func(t *testing.T) {
		tx, err := x.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `LOCK TABLE ops_wallet_v2.wallet_links IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		done := make(chan error, 1)
		go func() {
			rows, err := store.LoadActiveMany(t.Context(), x.ns, x.state, actors)
			if rows != nil {
				done <- errors.New("timeout returned partial scope")
				return
			}
			done <- err
		}()
		waitCtx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			var waiting bool
			if err := tx.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='ops_wallet_v2.wallet_links'::regclass AND mode='AccessShareLock' AND NOT granted)`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case <-waitCtx.Done():
				t.Fatal("real reader never waited on relation lock")
			case <-tick.C:
			}
		}
		if err := <-done; !errors.Is(err, w.ErrUnavailable) {
			t.Fatal("unbounded query", err)
		}
		if elapsed := time.Since(start); elapsed < 1500*time.Millisecond || elapsed > 4*time.Second {
			t.Fatal("query deadline", elapsed)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadActiveMany(t.Context(), x.ns, x.state, actors); err != nil {
			t.Fatal("pool recovery", err)
		}
		ctx, stop := context.WithCancel(t.Context())
		stop()
		if rows, err := store.LoadActiveMany(ctx, x.ns, x.state, actors); !errors.Is(err, w.ErrUnavailable) || rows != nil {
			t.Fatal("cancelled read", err)
		}
	})

	t.Run("new_recovery_generation_and_imported_tombstone", func(t *testing.T) {
		old, err := reader.Open(t.Context(), scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		generation := uuid.NewString()
		if err := walletsql.BeginRecovery(t.Context(), x.ownerDSN, x.binding, generation); err != nil {
			t.Fatal(err)
		}
		if err := old.CheckCurrent(t.Context()); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("old generation served during recovery", err)
		}
		batch := walletsql.RevocationBatch{APIVersion: "ops.wallet-revocations/v1", Kind: "WalletRevocationBatch", Namespace: x.ns.String(), SourceExportDigest: walletsql.DigestString(sha256.Sum256([]byte("b0-test-revocation-export"))), Aliases: []walletsql.Alias{{LegacySubject: "legacy-b0-holder", ActorID: actorA, EvidenceDigest: walletsql.DigestString(sha256.Sum256([]byte("b0-test-verified-alias"))), IdentityAuthority: "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", SourceTenant: f.Tenant, SourceKind: "human"}}, Revocations: []walletsql.Revocation{{LegacySubject: "legacy-b0-holder", Address: "0x000000000000000000000000000000000000ffff", RevokedAt: time.Unix(f.Now-1, 0).UTC().Format(time.RFC3339)}}}
		raw, _ := json.Marshal(batch)
		if _, err := walletsql.ImportRevocations(t.Context(), x.ownerDSN, x.binding, generation, raw, sha256.Sum256(raw)); err != nil {
			t.Fatal(err)
		}
		x.state = w.ExpectedState{Generation: generation, Coverage: sha256.Sum256([]byte("b0-test-complete-revocation-source"))}
		freshConfig := walletDataConfig(x, store)
		fresh, err := disclosurewallet.New(freshConfig)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("unready new state served", err)
		}
		if err := walletsql.FinalizeRecovery(t.Context(), x.ownerDSN, x.binding, x.state, true); err != nil {
			t.Fatal(err)
		}
		if err := old.CheckCurrent(t.Context()); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("old state served after restore", err)
		}
		s, err := fresh.Open(t.Context(), scope, nil)
		if err != nil || len(s.Wallets()) != 1 {
			t.Fatal("revocations resurrected", err)
		}
		ref := d.SourceRef{Kind: d.WalletSource, ID: old.Descriptor().Reference}
		if _, err := fresh.Open(t.Context(), scope, &ref); !errors.Is(err, d.ErrConflict) {
			t.Fatal("old reference rebound", err)
		}
		reader = fresh
	})

	t.Run("complete_4096_then_one_global_4097_overflow", func(t *testing.T) {
		current, err := store.LoadActiveMany(t.Context(), x.ns, x.state, actors)
		if err != nil {
			t.Fatal(err)
		}
		// Owner-only SQL SHAPE fixtures exercise bounds; they are NOT signed
		// ownership evidence. The actual signed positives above remain separate.
		insert := func(first, last int) {
			t.Helper()
			_, err := x.owner.Exec(t.Context(), `INSERT INTO ops_wallet_v2.wallet_links(namespace,actor_id,address,proof_kind,message,signature,message_hash,accepted_at,revoked)
 SELECT $1,CASE WHEN n%2=0 THEN $2 ELSE $3 END,decode(lpad(to_hex(n),40,'0'),'hex'),'eip191_v2',decode('01','hex'),decode(repeat('00',65),'hex'),decode(repeat('00',32),'hex'),$4,false FROM generate_series($5::integer,$6::integer)n`, x.ns[:], actorA, actorB, time.Unix(f.Now, 0).UTC(), first, last)
			if err != nil {
				t.Fatal(err)
			}
		}
		count := 4096 - len(current)
		insert(1, count)
		s, err := reader.Open(t.Context(), scope, nil)
		if err != nil || len(s.Wallets()) != 4096 {
			t.Fatal("complete4096", err)
		}
		insert(count+1, count+1)
		rows, err := store.LoadActiveMany(t.Context(), x.ns, x.state, actors)
		if err != nil || len(rows) != 4097 {
			t.Fatal("global sentinel", len(rows), err)
		}
		if s, err := reader.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrTooBroad) || s != nil {
			t.Fatal("overflow became partial successful scope", err)
		}
	})
}
