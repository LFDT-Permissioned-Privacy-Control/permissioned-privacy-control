package activitysql_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	s "privacy-proxy/internal/operational/activitysql"
)

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}
func TestRestrictedCatalogACLRecoveryAndRetainedOriginalRun(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	t.Run("actual normalized catalog equal under all roles", func(t *testing.T) {
		query, err := os.ReadFile("migrations/catalog-query.sql")
		if err != nil {
			t.Fatal(err)
		}
		expected, err := os.ReadFile("migrations/005-catalog.json")
		if err != nil {
			t.Fatal(err)
		}
		var want any
		if json.Unmarshal(expected, &want) != nil {
			t.Fatal("expected catalog")
		}
		normalized, _ := json.Marshal(want)
		for _, dsn := range []string{x.dsn, x.writer, x.reader, x.retention} {
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			var raw []byte
			err = conn.QueryRow(ctx, string(query)).Scan(&raw)
			conn.Close(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var got any
			if json.Unmarshal(raw, &got) != nil {
				t.Fatal("actual catalog")
			}
			actual, _ := json.Marshal(got)
			if string(actual) != string(normalized) {
				t.Fatal("owner/restricted catalog differs")
			}
		}
	})
	writer, err := s.OpenWriter(ctx, x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	producer := uuid.NewString()
	run, err := writer.StartRun(ctx, a.RunRequest{ProducerID: producer, RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	sealed := testEntry(t, run.Binding(), 1, 1000000)
	pending := testEntry(t, run.Binding(), 2, 2000000)
	if err := run.SealOne(ctx, sealed.Seq, sealed.Data); err != nil {
		t.Fatal(err)
	}
	active, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("restricted negative grants and active run stays", func(t *testing.T) {
		reader, err := pgx.Connect(ctx, x.reader)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close(ctx)
		for _, query := range []string{`SELECT request_params FROM public.access_logs`, `SELECT nextval('public.access_logs_id_seq')`, `UPDATE ops_activity_v1.sources SET ready=false`} {
			if _, err := reader.Exec(ctx, query); sqlState(err) != "42501" {
				t.Fatal("reader grant", query, err)
			}
		}
		retention, err := pgx.Connect(ctx, x.retention)
		if err != nil {
			t.Fatal(err)
		}
		defer retention.Close(ctx)
		if _, err := retention.Exec(ctx, `DELETE FROM ops_activity_v1.runs WHERE run_id=$1::uuid`, active.Binding().RunID); sqlState(err) != "42501" {
			t.Fatal("unsealed active registration was deletable", err)
		}
		for _, query := range []string{`DELETE FROM ops_activity_v1.runs`, `DELETE FROM public.access_logs`, `UPDATE ops_activity_v1.sources SET ready=false`} {
			if _, err := retention.Exec(ctx, query); sqlState(err) != "42501" {
				t.Fatal("retention grant", query, err)
			}
		}
		if _, err := x.owner.Exec(ctx, `DELETE FROM public.access_logs WHERE chain_name=$1`, "ops-activity-v1/"+hexDigest(a.Digest(x.scope.NetworkKey))); sqlState(err) != "P0001" {
			t.Fatal("generic owner deletion without intent+chainlock", err)
		}
	})
	if err := active.SealOne(ctx, active.Binding().Base+1, testEntry(t, active.Binding(), 1, 1500000).Data); err != nil {
		t.Fatal("active run cannot seal after denied deletion", err)
	}
	var startupID, rangeBefore int64
	var startupCalled bool
	if x.owner.QueryRow(ctx, `SELECT last_value,is_called FROM public.access_logs_id_seq`).Scan(&startupID, &startupCalled) != nil || x.owner.QueryRow(ctx, `SELECT last_value FROM public.access_logs_buffer_range_seq`).Scan(&rangeBefore) != nil {
		t.Fatal("save startup allocators")
	}
	if _, err := x.owner.Exec(ctx, `SELECT setval('public.access_logs_id_seq',1,false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()}); !errors.Is(err, a.ErrQuarantined) {
		t.Fatal("behind ID startup was not refused", err)
	}
	var afterProbe, rangeAfter int64
	var probeCalled bool
	if x.owner.QueryRow(ctx, `SELECT last_value,is_called FROM public.access_logs_id_seq`).Scan(&afterProbe, &probeCalled) != nil || afterProbe != 1 || !probeCalled || x.owner.QueryRow(ctx, `SELECT last_value FROM public.access_logs_buffer_range_seq`).Scan(&rangeAfter) != nil || rangeAfter != rangeBefore {
		t.Fatal("startup burned through stale IDs or drew a range before refusal", afterProbe, probeCalled, rangeAfter)
	}
	if _, err := x.owner.Exec(ctx, `SELECT setval('public.access_logs_id_seq',$1,$2)`, startupID, startupCalled); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()}); err != nil {
		t.Fatal("explicit owner ID repair did not allow a fresh startup", err)
	}
	for _, ddl := range []struct{ name, alter, repair string }{
		{"enabled RLS", `ALTER TABLE ops_activity_v1.sources ENABLE ROW LEVEL SECURITY`, `ALTER TABLE ops_activity_v1.sources DISABLE ROW LEVEL SECURITY`},
		{"forced RLS", `ALTER TABLE public.access_logs FORCE ROW LEVEL SECURITY`, `ALTER TABLE public.access_logs NO FORCE ROW LEVEL SECURITY`},
		{"extra column", `ALTER TABLE ops_activity_v1.runs ADD COLUMN unqualified boolean`, `ALTER TABLE ops_activity_v1.runs DROP COLUMN unqualified`},
		{"PUBLIC grant", `GRANT SELECT ON ops_activity_v1.sources TO PUBLIC`, `REVOKE SELECT ON ops_activity_v1.sources FROM PUBLIC`},
		{"non-updatable anchor", `CREATE OR REPLACE VIEW ops_activity_v1.anchors AS SELECT chain_name,max(last_pruned_id)last_pruned_id,max(last_pruned_entry_hash)last_pruned_entry_hash,max(last_pruned_at)last_pruned_at FROM public.audit_chain_anchor WHERE chain_name~'^ops-activity-v1/[0-9a-f]{64}$' GROUP BY chain_name`, `CREATE OR REPLACE VIEW ops_activity_v1.anchors AS SELECT chain_name,last_pruned_id,last_pruned_entry_hash,last_pruned_at FROM public.audit_chain_anchor WHERE chain_name~'^ops-activity-v1/[0-9a-f]{64}$' WITH LOCAL CHECK OPTION`},
	} {
		t.Run(ddl.name, func(t *testing.T) {
			if _, err := x.owner.Exec(ctx, ddl.alter); err != nil {
				t.Fatal(err)
			}
			if bad, err := s.OpenReader(ctx, x.reader, x.scope); err == nil {
				bad.Close()
				t.Fatal("altered shape/permission was accepted")
			}
			if _, err := x.owner.Exec(ctx, ddl.repair); err != nil {
				t.Fatal(err)
			}
			if repaired, err := s.OpenReader(ctx, x.reader, x.scope); err != nil {
				t.Fatal("repaired role", err)
			} else {
				repaired.Close()
			}
		})
	}
	if err := s.BeginRecovery(ctx, x.dsn, x.scope, false); !errors.Is(err, a.ErrInvalid) {
		t.Fatal("undrained recovery", err)
	}
	if err := s.BeginRecovery(ctx, x.dsn, x.scope, true); err != nil {
		t.Fatal(err)
	}
	if err := run.SealOne(ctx, pending.Seq, pending.Data); err == nil {
		t.Fatal("old open writer rebound after generation rotation")
	}
	status, err := s.Status(ctx, x.dsn, x.scope.NetworkKey, x.scope.SourceID)
	if err != nil || status.Ready || status.Metadata.Generation == x.scope.ExpectedGeneration {
		t.Fatal(status, err)
	}
	newScope := x.scope
	newScope.ExpectedGeneration = status.Metadata.Generation
	if err := s.FinalizeRecovery(ctx, x.dsn, newScope, false, time.Minute); !errors.Is(err, a.ErrInvalid) {
		t.Fatal("missing acknowledgement", err)
	}
	// A real persisted-counter mismatch fails the FULL recovery recount; cold
	// reads deliberately don't scan every retained row to prove equality.
	if _, err := x.owner.Exec(ctx, `UPDATE ops_activity_v1.sources SET byte_count=byte_count+1`); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeRecovery(ctx, x.dsn, newScope, true, time.Minute); err == nil {
		t.Fatal("recovery blessed changed counters")
	}
	if _, err := x.owner.Exec(ctx, `UPDATE ops_activity_v1.sources SET byte_count=byte_count-1`); err != nil {
		t.Fatal(err)
	}
	var savedID int64
	var savedCalled bool
	if x.owner.QueryRow(ctx, `SELECT last_value,is_called FROM public.access_logs_id_seq`).Scan(&savedID, &savedCalled) != nil {
		t.Fatal("save public fixture allocator")
	}
	if _, err := x.owner.Exec(ctx, `SELECT setval('public.access_logs_id_seq',1,false)`); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeRecovery(ctx, x.dsn, newScope, true, time.Minute); err == nil {
		t.Fatal("table-only restore ID allocator was blessed ready")
	}
	var unchanged int64
	var called bool
	if x.owner.QueryRow(ctx, `SELECT last_value,is_called FROM public.access_logs_id_seq`).Scan(&unchanged, &called) != nil || unchanged != 1 || called {
		t.Fatal("recovery silently advanced ID allocator", unchanged, called)
	}
	if _, err := x.owner.Exec(ctx, `SELECT setval('public.access_logs_id_seq',$1,$2)`, savedID, savedCalled); err != nil {
		t.Fatal(err)
	}
	registration := x.registration
	registration.Configuration = [32]byte{9}
	if err := s.Reconfigure(ctx, x.dsn, newScope, registration, true); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeRecovery(ctx, x.dsn, newScope, true, time.Minute); err != nil {
		t.Fatal("full original-run recovery", err)
	}
	newWriter, err := s.OpenWriter(ctx, x.writer, newScope)
	if err != nil {
		t.Fatal(err)
	}
	defer newWriter.Close()
	newRun, err := newWriter.StartRun(ctx, a.RunRequest{ProducerID: producer, RunID: uuid.NewString(), AllocatedThrough: pending.Seq})
	if err != nil {
		t.Fatal(err)
	}
	if err := newRun.SealOne(ctx, pending.Seq, pending.Data); err != nil {
		t.Fatal("registered ORIGINAL generation/config replay rejected", err)
	}
	v, err := newRun.Verify(ctx, []buffer.Entry{pending})
	if err != nil || len(v) != 1 || v[0] != sealer.Sealed {
		t.Fatal(v, err)
	}
}

func TestRecorderActualPGCrashPruneAndBackdatedCompletion(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	w, err := s.OpenWriter(ctx, x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	producer := uuid.NewString()
	cfg := a.Config{Network: x.registration.Network, SourceID: x.scope.SourceID, ProducerID: producer, ExpectedGeneration: x.scope.ExpectedGeneration, Configuration: a.Digest(x.registration.Configuration), Methods: []string{"eth_call"}, Clock: func() time.Time { return time.UnixMicro(1000000) }, BufferDirectory: t.TempDir(), Limits: a.DefaultLimits()}
	recorder, err := a.New(ctx, cfg, w)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := recorder.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := slot.Complete(a.Completion{Method: "eth_call", HTTPStatus: 200, Outcome: a.Success})
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate seal COMMIT followed by crash BEFORE local cleanup: the exact
	// original spool is read and sealed through another registered run facade.
	spool, err := buffer.Open(cfg.BufferDirectory, buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := spool.DrainBounded(0, 512, a.MaxEncodedBytes, a.MaxBatchBytes)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	spool.Close()
	run, err := w.StartRun(ctx, a.RunRequest{ProducerID: producer, RunID: uuid.NewString(), AllocatedThrough: receipt.Sequence()})
	if err != nil {
		t.Fatal(err)
	}
	if err := run.SealBatch(ctx, entries); err != nil {
		t.Fatal(err)
	}
	r, err := s.OpenRetention(ctx, x.retention, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if n, err := r.Prune(ctx, 2000000, 5000); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if restored, err := a.New(ctx, cfg, w); !errors.Is(err, a.ErrQuarantined) {
		if restored != nil {
			restored.Close(ctx)
		}
		t.Fatal("pruned original spool did not require offline recovery", err)
	}
	spool, err = buffer.Open(cfg.BufferDirectory, buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	entries, err = spool.DrainBounded(0, 512, a.MaxEncodedBytes, a.MaxBatchBytes)
	spool.Close()
	if err != nil || len(entries) != 1 || entries[0].Seq != receipt.Sequence() {
		t.Fatal("original evidence removed", entries, err)
	}
	// Fresh completion with a truthful clock behind the already-published
	// floor also remains local and quarantines; no force-forward or discard.
	cfg.BufferDirectory = t.TempDir()
	fresh, err := a.New(ctx, cfg, w)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close(ctx)
	slot, _ = fresh.Reserve()
	if _, err := slot.Complete(a.Completion{Method: "eth_call", HTTPStatus: 200, Outcome: a.Success}); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- fresh.Run(runCtx) }()
	deadline := time.Now().Add(3 * time.Second)
	for fresh.Healthy() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if fresh.Healthy() == nil {
		t.Fatal("backdated pre-floor completion remained ready")
	}
	if err := fresh.Close(ctx); err != nil {
		t.Fatal(err)
	}
	spool, err = buffer.Open(cfg.BufferDirectory, buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	entries, err = spool.DrainBounded(0, 512, a.MaxEncodedBytes, a.MaxBatchBytes)
	spool.Close()
	if err != nil || len(entries) != 1 {
		t.Fatal("backdated evidence deleted", entries, err)
	}
}

func TestRegisteredRangeBufferAheadAndSignedMaximum(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	writer, err := s.OpenWriter(ctx, x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	producer := uuid.NewString()
	if _, err := x.owner.Exec(ctx, `SELECT setval('public.access_logs_buffer_range_seq',10,false)`); err != nil {
		t.Fatal(err)
	}
	original, err := writer.StartRun(ctx, a.RunRequest{ProducerID: producer, RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.owner.Exec(ctx, `SELECT setval('public.access_logs_buffer_range_seq',5,false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.StartRun(ctx, a.RunRequest{ProducerID: producer, RunID: uuid.NewString(), AllocatedThrough: original.Binding().Base + 1}); !errors.Is(err, sealer.ErrChainAhead) {
		t.Fatal("fresh range below local allocation was silently skipped", err)
	}
	var value int64
	if x.owner.QueryRow(ctx, `SELECT last_value FROM public.access_logs_buffer_range_seq`).Scan(&value) != nil || value != 5 {
		t.Fatal("range catch-up loop", value)
	}
	if _, err := x.owner.Exec(ctx, `SELECT setval('public.access_logs_buffer_range_seq',8388607,false)`); err != nil {
		t.Fatal(err)
	}
	last, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal("last legal range", err)
	}
	if last.Binding().Top != 1<<63-1 {
		t.Fatal("signed maximum overflow", last.Binding())
	}
	entry := testEntry(t, last.Binding(), 1, 3000000)
	entry.Seq = last.Binding().Top
	if err := last.SealOne(ctx, entry.Seq, entry.Data); err != nil {
		t.Fatal("actual signed maximum sequence", err)
	}
	if hw, err := last.HighWater(ctx); err != nil || hw != entry.Seq {
		t.Fatal(hw, err)
	}
	if _, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()}); err == nil {
		t.Fatal("exhausted global range allocator accepted")
	}
}
