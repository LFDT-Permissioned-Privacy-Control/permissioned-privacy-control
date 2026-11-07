package admissionsql_test

import (
	"bytes"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPostgresDisclosureFinance(t *testing.T) {
	db := setup(t)
	x := newFixture(t, db, source())
	store, err := admissionsql.OpenReader(t.Context(), db.readerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	digest := d.Digest("sha256:" + strings.Repeat("6", 64))
	plan := d.SourcePlan{Version: 1, Profile: "ops.disclosure.data-sources/v1", BundleDigest: digest, NetworkKey: d.Digest(x.key.String()), PlanDigest: digest, Resources: []p.Resource{p.ComplianceReport}}
	clock := func() time.Time { return time.Unix(x.clock.Load(), 0).UTC() }
	cfg := admissionsql.FinanceReaderConfig{Store: store, Network: x.binding, ExpectedState: x.state, Plan: plan, Clock: clock}
	reader, err := admissionsql.NewFinanceReader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	original := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{p.ComplianceReport}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 3600, End: f.Now}, Level: p.Full}
	normalized, err := d.Normalize(d.Query{Version: 1, Resource: p.ComplianceReport, View: d.Report}, original)
	if err != nil {
		t.Fatal(err)
	}
	scope := d.ReadScope{Namespace: digest, CaseID: uuid.NewString(), CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: digest, RuleDigest: digest, EffectiveUntil: clock().Add(time.Minute), Query: normalized}
	insert := func(q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, org, actor string, at time.Time) int64 {
		t.Helper()
		var id int64
		err := q.QueryRow(t.Context(), `INSERT INTO ops_admission_v2.compliance_events(network_key,tx_hash,actor_id,org_id,kind,coverage,decision,monitored,reason,decision_at,policy_digest,anchor_hash,anchor_number,anchor_timestamp,evidence_profile)VALUES($1,$2,$3,$4::uuid,'admission_only','not_detected','allowed',false,'',$5,$6,$7,1,1,$8) RETURNING id`, x.key[:], bytes.Repeat([]byte{3}, 32), actor, org, at, bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), rpcexecution.GuardRetainedProfileID).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	reset := func() {
		t.Helper()
		if _, err := db.owner.Exec(t.Context(), `DELETE FROM ops_admission_v2.compliance_events WHERE network_key=$1`, x.key[:]); err != nil {
			t.Fatal(err)
		}
	}
	open := func() *admissionsql.FinanceSnapshot {
		t.Helper()
		s, err := reader.Open(t.Context(), scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("zero is retained-only and no held read transaction", func(t *testing.T) {
		s := open()
		defer s.Close()
		if len(s.Evidence()) != 0 || s.Descriptor().Population != "RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT" {
			t.Fatal("zero population")
		}
		var held int
		err := db.owner.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE usename='admission_reader' AND xact_start IS NOT NULL`).Scan(&held)
		if err != nil || held != 0 {
			t.Fatal("held transaction", held, err)
		}
	})
	t.Run("original org actor inclusive end and explicit-address filtering", func(t *testing.T) {
		defer reset()
		insert(db.owner, f.OtherOrg, f.Actor(f.Subject), clock())
		insert(db.owner, f.Org, f.Actor(f.AdminSubject), clock())
		insert(db.owner, f.Org, f.Actor(f.Subject), clock().Add(time.Microsecond))
		id := insert(db.owner, f.Org, f.Actor(f.Subject), clock())
		s := open()
		if len(s.Evidence()) != 1 || string(s.Evidence()[0].ID) != strconvInt(id) {
			t.Fatal("scope", s.Evidence())
		}
		s.Close()
		addr := "0x" + strings.Repeat("a", 40)
		n, e := d.Normalize(d.Query{Version: 1, Resource: p.ComplianceReport, View: d.Report, Addresses: []string{addr}}, original)
		if e != nil {
			t.Fatal(e)
		}
		narrow := scope
		narrow.Query = n
		s, e = reader.Open(t.Context(), narrow, nil)
		if e != nil || len(s.Evidence()) != 0 {
			t.Fatal("admission-only address inference", e)
		}
		s.Close()
	})
	t.Run("late low ID commit and unrelated writes", func(t *testing.T) {
		defer reset()
		tx, err := db.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		low := insert(tx, f.Org, f.Actor(f.Subject), clock())
		other, err := pgx.Connect(t.Context(), db.ownerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(context.Background())
		high := insert(other, f.Org, f.Actor(f.Subject), clock())
		if low >= high {
			t.Fatal("fixture ID order")
		}
		s := open()
		defer s.Close()
		if len(s.Evidence()) != 1 {
			t.Fatal("uncommitted row visible")
		}
		insert(other, f.OtherOrg, f.Actor(f.Subject), clock())
		x.clock.Add(1)
		if err = s.CheckCurrent(t.Context()); err != nil {
			t.Fatal("unrelated/clock invalidation", err)
		}
		if err = tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err = s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrConflict) {
			t.Fatal("low commit not detected", err)
		}
		ref := d.SourceRef{Kind: d.FinanceSource, ID: s.Descriptor().Reference}
		if _, err = reader.Open(t.Context(), scope, &ref); !errors.Is(err, d.ErrConflict) {
			t.Fatal("old sample resumed", err)
		}
		x.clock.Add(-1)
	})
	t.Run("100 full rows vs101 and foreign rows do not consume budget", func(t *testing.T) {
		defer reset()
		for i := 0; i < 102; i++ {
			insert(db.owner, f.OtherOrg, f.Actor(f.Subject), clock())
		}
		for i := 0; i < 100; i++ {
			insert(db.owner, f.Org, f.Actor(f.Subject), clock())
		}
		s := open()
		if len(s.Evidence()) != 100 {
			t.Fatal("row count")
		}
		last := int64(0)
		for _, e := range s.Evidence() {
			id := parseInt(t, string(e.ID))
			if id <= last {
				t.Fatal("not ID ascending")
			}
			last = id
		}
		s.Close()
		insert(db.owner, f.Org, f.Actor(f.Subject), clock())
		if s, err := reader.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrTooBroad) || s != nil {
			t.Fatal("silent truncation", s, err)
		}
	})
	t.Run("prune body change and detached result", func(t *testing.T) {
		defer reset()
		id := insert(db.owner, f.Org, f.Actor(f.Subject), clock())
		s := open()
		out := s.Evidence()
		out[0].Provenance.TargetActorIDs[0] = "corrupt"
		if s.Evidence()[0].Provenance.TargetActorIDs[0] != f.Actor(f.Subject) {
			t.Fatal("alias")
		}
		if _, err := db.owner.Exec(t.Context(), `DELETE FROM ops_admission_v2.compliance_events WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if err := s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrConflict) {
			t.Fatal("prune missed", err)
		}
		s.Close()
		if s.CheckCurrent(t.Context()) == nil || s.Evidence() != nil {
			t.Fatal("closed")
		}
	})
	t.Run("RLS empty is unavailable repaired is zero", func(t *testing.T) {
		for _, sql := range []string{`ALTER TABLE ops_admission_v2.compliance_events ENABLE ROW LEVEL SECURITY`, `ALTER TABLE ops_admission_v2.compliance_events FORCE ROW LEVEL SECURITY`} {
			if _, err := db.owner.Exec(t.Context(), sql); err != nil {
				t.Fatal(err)
			}
			if s, err := reader.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrUnavailable) || s != nil {
				t.Fatal("RLS false zero", s, err)
			}
		}
		if _, err := db.owner.Exec(t.Context(), `ALTER TABLE ops_admission_v2.compliance_events DISABLE ROW LEVEL SECURITY; ALTER TABLE ops_admission_v2.compliance_events NO FORCE ROW LEVEL SECURITY`); err != nil {
			t.Fatal(err)
		}
		s := open()
		s.Close()
	})
	t.Run("old original quote is preserved and invalid numeric or digest is unavailable", func(t *testing.T) {
		defer reset()
		id := insert(db.owner, f.Org, f.Actor(f.Subject), clock())
		qs, e := a.NewQuoteSnapshot([]a.Quote{{ID: "old-price", Currency: "usd", Value: 2, FetchedAt: clock().Add(-24 * time.Hour), ProviderAsOf: clock().Add(-24 * time.Hour), SourceID: "original-provider"}})
		if e != nil {
			t.Fatal(e)
		}
		q := qs.Quotes()[0]
		_, e = db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.compliance_events SET kind='root_native',coverage='root_transfer',from_address=$2,to_address=$3,amount_wei='1',amount_fiat=2,threshold_fiat=100,currency='usd',monitored=true,quote_digest=$4,quote_id=$5,quote_source=$6,quote_value=$7::numeric,quote_as_of=$8,quote_observed_at=$9 WHERE id=$1`, id, bytes.Repeat([]byte{0xaa}, 20), bytes.Repeat([]byte{0xbb}, 20), q.Digest[:], q.ID, q.SourceID, "2", q.ProviderAsOf, q.FetchedAt)
		if e != nil {
			t.Fatal(e)
		}
		s := open()
		defer s.Close()
		evidence := s.Evidence()
		if evidence[0].Quote == nil || evidence[0].Quote.FetchedAt != q.FetchedAt || evidence[0].Quote.Digest != d.Digest(q.Digest.String()) {
			t.Fatal("old quote relabeled", evidence)
		}
		evidence[0].Quote.ID = "changed"
		*evidence[0].QuoteDigest = "changed"
		if s.Evidence()[0].Quote.ID != q.ID {
			t.Fatal("quote alias")
		}
		if _, err := db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.compliance_events SET reason='changed body' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if err := s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrConflict) {
			t.Fatal("body currentness", err)
		}
		for _, update := range []string{`quote_digest=decode(repeat('11',32),'hex')`, `quote_value='NaN'::numeric`, `quote_value=1e-500`, `quote_observed_at='infinity'::timestamptz`, `anchor_number=1e-500`, `anchor_timestamp=1e-500`} {
			if _, err := db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.compliance_events SET quote_digest=$2,quote_value=2,quote_observed_at=$3,anchor_number=1,anchor_timestamp=1 WHERE id=$1`, id, q.Digest[:], q.FetchedAt); err != nil {
				t.Fatal(err)
			}
			// NaN is already rejected by the table's existing range constraint.
			if _, err := db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.compliance_events SET `+update+` WHERE id=$1`, id); err != nil {
				if strings.Contains(update, "NaN") {
					continue
				}
				t.Fatal(err)
			}
			if got, err := reader.Open(t.Context(), scope, nil); got != nil || !errors.Is(err, d.ErrUnavailable) {
				t.Fatal("invalid original quote", update, got, err)
			}
		}
	})
	t.Run("existing retention changes retained sample without inventing floor", func(t *testing.T) {
		defer reset()
		insert(db.owner, f.Org, f.Actor(f.Subject), clock())
		s := open()
		defer s.Close()
		ret, err := admissionsql.OpenRetention(t.Context(), db.retentionDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer ret.Close()
		n, err := ret.CleanupOnce(t.Context(), x.key, x.state, clock().Add(2*time.Hour), admissionsql.Retention{Logs: time.Hour, Batch: 100})
		if err != nil || n != 1 {
			t.Fatal("real retention", n, err)
		}
		if err := s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrConflict) {
			t.Fatal("retention sample", err)
		}
		empty := open()
		defer empty.Close()
		if len(empty.Evidence()) != 0 {
			t.Fatal("retained zero")
		}
		var floor *time.Time
		if err := db.owner.QueryRow(t.Context(), `SELECT history_floor FROM ops_admission_v2.network_state WHERE network_key=$1`, x.key[:]).Scan(&floor); err != nil || floor != nil {
			t.Fatal("invented floor", floor, err)
		}
	})
	t.Run("earlier deadline bounds locked SQL and returns no partial sample", func(t *testing.T) {
		tx, err := db.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `LOCK TABLE ops_admission_v2.compliance_events IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
		defer cancel()
		start := time.Now()
		s, err := reader.Open(ctx, scope, nil)
		if s != nil || !errors.Is(err, d.ErrUnavailable) || time.Since(start) > time.Second {
			t.Fatal("bounded SQL", s, err, time.Since(start))
		}
	})
	t.Run("view cannot turn hidden rows into authoritative empty", func(t *testing.T) {
		if _, err := db.owner.Exec(t.Context(), `ALTER TABLE ops_admission_v2.compliance_events RENAME TO finance_test_events; CREATE VIEW ops_admission_v2.compliance_events AS SELECT * FROM ops_admission_v2.finance_test_events WHERE false; GRANT SELECT ON ops_admission_v2.compliance_events TO admission_reader`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.owner.Exec(t.Context(), `DROP VIEW ops_admission_v2.compliance_events;ALTER TABLE ops_admission_v2.finance_test_events RENAME TO compliance_events`); err != nil {
				t.Fatal(err)
			}
		}()
		if s, err := reader.Open(t.Context(), scope, nil); s != nil || !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("nonordinary zero", s, err)
		}
	})
	t.Run("source state unavailable until expected recovery state selected", func(t *testing.T) {
		for _, update := range []string{`ready=false`, `generation='77777777-7777-4777-8777-777777777777'::uuid`} {
			if _, err := db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.network_state SET `+update+` WHERE network_key=$1`, x.key[:]); err != nil {
				t.Fatal(err)
			}
			if s, err := reader.Open(t.Context(), scope, nil); s != nil || !errors.Is(err, d.ErrUnavailable) {
				t.Fatal("state mismatch", s, err)
			}
			if _, err := db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.network_state SET ready=true,generation=$2::uuid WHERE network_key=$1`, x.key[:], x.state.Generation); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("wrong mode invalid scope and canceled context return no snapshot", func(t *testing.T) {
		bad := cfg
		bad.Store = db.one
		if _, err := admissionsql.NewFinanceReader(bad); !errors.Is(err, d.ErrInvalid) {
			t.Fatal("app miswire")
		}
		badScope := scope
		badScope.Query = d.NormalizedQuery{}
		if _, err := reader.Open(t.Context(), badScope, nil); !errors.Is(err, d.ErrInvalid) {
			t.Fatal("scope")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if s, err := reader.Open(ctx, scope, nil); s != nil || !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("cancel", s, err)
		}
	})
	t.Run("actual read COMMIT connection loss returns no snapshot", func(t *testing.T) { financeReadCommitFailure(t, cfg, db.readerDSN, scope) })
}

func strconvInt(v int64) string { return strconv.FormatInt(v, 10) }
func parseInt(t *testing.T, v string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
