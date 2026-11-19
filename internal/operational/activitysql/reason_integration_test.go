package activitysql_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
	r "privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	f "privacy-proxy/internal/disclosuretest"
	s "privacy-proxy/internal/operational/activitysql"
)

func reasonEntry(t *testing.T, entry buffer.Entry, reason r.Code) buffer.Entry {
	t.Helper()
	record, err := a.DecodeSpool(entry.Data)
	if err != nil {
		t.Fatal(err)
	}
	e := record.Fields()
	e.Version = 2
	e.Reason = reason
	e.BufferSeq = "1"
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	entry.Data = append(bytes.Clone(raw[:len(raw)-len(`,"b":"1"}`)]), '}')
	if _, err = a.DecodeSpool(entry.Data); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestReasonActualPGPrototypeUpgradeOnlineIndexAndMixedRecovery(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	writer, err := s.OpenWriter(ctx, x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	run, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	old := testEntry(t, run.Binding(), 1, 1000000)
	if err = run.SealOne(ctx, old.Seq, old.Data); err != nil {
		t.Fatal(err)
	}
	var original string
	if err = x.owner.QueryRow(ctx, `SELECT request_params FROM ops_activity_v1.qualified_logs LIMIT 1`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	before, err := s.Status(ctx, x.dsn, x.scope.NetworkKey, x.scope.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the exact unreleased006 guard with exclusively v1 history.
	// This is test setup, not a production downgrade or history rewrite.
	raw, err := os.ReadFile("migrations/006-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Functions []struct{ Name, Definition string }
	}
	if json.Unmarshal(raw, &catalog) != nil {
		t.Fatal("catalog")
	}
	legacyGuard := ""
	for _, fn := range catalog.Functions {
		if fn.Name == "ops_activity_v1.guard_log()" {
			legacyGuard = fn.Definition
		}
	}
	if legacyGuard == "" {
		t.Fatal("guard fixture")
	}
	for _, prototype := range []string{"006", "005"} {
		if _, err = x.owner.Exec(ctx, legacyGuard); err != nil {
			t.Fatal(err)
		}
		if prototype == "005" {
			if err = s.DowngradeTo005(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); err != nil {
				t.Fatal("exact006->005", err)
			}
		}
		if bad, err := s.OpenReader(ctx, x.reader, x.scope); err == nil {
			bad.Close()
			t.Fatal("007 reader accepted old guard")
		}
		if err = s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); err != nil {
			t.Fatal("prototype->007", prototype, err)
		}
	}
	after, err := s.Status(ctx, x.dsn, x.scope.NetworkKey, x.scope.SourceID)
	if err != nil || before != after {
		t.Fatal("upgrade changed source/run/head/count/generation", before, after, err)
	}
	var unchanged string
	if err = x.owner.QueryRow(ctx, `SELECT request_params FROM ops_activity_v1.qualified_logs LIMIT 1`).Scan(&unchanged); err != nil || unchanged != original {
		t.Fatal("v1 bytes changed", err)
	}
	reader, err := s.OpenReader(ctx, x.reader, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	check := func() {
		t.Helper()
		if err := reader.CheckReady(ctx); err != nil {
			t.Fatal("active reader", err)
		}
		if err := writer.CheckReady(ctx); err != nil {
			t.Fatal("active writer", err)
		}
	}
	ordinal := int64(1)
	appendWhileOnline := func() {
		t.Helper()
		check()
		ordinal++
		e := testEntry(t, run.Binding(), ordinal, ordinal*1000000)
		if err := run.SealOne(ctx, e.Seq, e.Data); err != nil {
			t.Fatal("write during index maintenance", err)
		}
		cut, err := reader.Open(ctx, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		cut.Close()
		if err = cut.CheckCurrent(ctx); err != nil {
			t.Fatal("read during index maintenance", err)
		}
	}
	indexSQL, err := os.ReadFile("migrations/006.sql")
	if err != nil {
		t.Fatal(err)
	}
	create := string(bytes.Replace(indexSQL, []byte("CREATE INDEX "), []byte("CREATE INDEX CONCURRENTLY "), 1))
	waitState := func(valid, ready bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var v, q bool
			err := x.owner.QueryRow(ctx, `SELECT indisvalid,indisready FROM pg_index WHERE indexrelid=to_regclass('public.activity_org_page')`).Scan(&v, &q)
			if err == nil && v == valid && q == ready {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("index lifecycle timeout", valid, ready, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Existing writer and old MVCC snapshot hold the actual two online phases.
	blocker, err := pgx.Connect(ctx, x.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(ctx)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `LOCK TABLE public.access_logs IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	snapshotConn, err := pgx.Connect(ctx, x.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshotConn.Close(ctx)
	snapshot, err := snapshotConn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = snapshot.Exec(ctx, `SELECT count(*) FROM public.access_logs`); err != nil {
		t.Fatal(err)
	}
	ddl, err := pgx.Connect(ctx, x.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ddl.Close(ctx)
	done := make(chan error, 1)
	go func() { _, err := ddl.Exec(ctx, create); done <- err }()
	waitState(false, false)
	appendWhileOnline()
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	waitState(false, true)
	appendWhileOnline()
	if err = snapshot.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal("concurrent create", err)
	}
	waitState(true, true)
	appendWhileOnline()
	if _, err = x.owner.Exec(ctx, `DROP INDEX CONCURRENTLY public.activity_org_page`); err != nil {
		t.Fatal(err)
	}
	appendWhileOnline()
	// Cancelled concurrent CREATE leaves its qualified invalid index; both roles
	// remain live and owner DROP CONCURRENTLY removes it without a fleet pause.
	tx, err = blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `LOCK TABLE public.access_logs IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ddlctx, cancel := context.WithCancel(ctx)
	go func() { _, err := ddl.Exec(ddlctx, create); done <- err }()
	waitState(false, false)
	cancel()
	if err = <-done; err == nil {
		t.Fatal("cancelled create succeeded")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	appendWhileOnline()
	if _, err = x.owner.Exec(ctx, `DROP INDEX CONCURRENTLY public.activity_org_page`); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`CREATE INDEX activity_org_page ON public.access_logs(id)`,
		`CREATE UNIQUE INDEX activity_org_page ON public.access_logs(chain_name,org_id,activity_observed_us DESC,activity_producer_id DESC,activity_run_id DESC,activity_ordinal DESC,activity_record_id DESC) WHERE(activity_kind=1)`,
		`CREATE INDEX activity_unqualified_extra ON public.access_logs(id)`,
	} {
		if _, err = x.owner.Exec(ctx, bad); err != nil {
			t.Fatal(err)
		}
		if err = reader.CheckReady(ctx); err == nil {
			t.Fatal("unqualified index accepted")
		}
		if _, err = x.owner.Exec(ctx, `DROP INDEX IF EXISTS public.activity_org_page,public.activity_unqualified_extra`); err != nil {
			t.Fatal(err)
		}
	}
	check()
	// A real old spool and v2 spool remain after their prefix committed to SQL:
	// compatible recovery must verify/settle them, not duplicate or rewrite either.
	producer := uuid.NewString()
	mixed, err := writer.StartRun(ctx, a.RunRequest{ProducerID: producer, RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	old = testEntry(t, mixed.Binding(), 1, 20000000)
	newEntry := reasonEntry(t, adminEnvelope(t, testEntry(t, mixed.Binding(), 2, 21000000), f.Org, f.Actor(f.Subject), "eth_call", true), r.SenderNotLinked)
	pendingEntry := reasonEntry(t, adminEnvelope(t, testEntry(t, mixed.Binding(), 3, 22000000), f.Org, f.Actor(f.Subject), "eth_call", false), r.NotRecorded)
	dir := t.TempDir()
	buf, err := buffer.Open(dir, buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	if err = buf.SeedRange(mixed.Binding().Base, mixed.Binding().Top); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []buffer.Entry{old, newEntry, pendingEntry} {
		seq, err := buf.Append(entry.Data)
		if err != nil || seq != entry.Seq {
			t.Fatal("seed mixed spool", err)
		}
	}
	if err = mixed.SealBatch(ctx, []buffer.Entry{old, newEntry}); err != nil {
		t.Fatal(err)
	}
	if err = buf.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := a.Config{Network: x.registration.Network, SourceID: x.scope.SourceID, ProducerID: producer, ExpectedGeneration: x.scope.ExpectedGeneration, Configuration: a.Digest(x.registration.Configuration), Methods: []string{"eth_call", "eth_sendRawTransaction"}, Clock: time.Now, BufferDirectory: dir, Limits: a.DefaultLimits()}
	recorder, err := a.New(ctx, cfg, writer)
	if err != nil {
		t.Fatal("mixed recovery", err)
	}
	runctx, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { finished <- recorder.Run(runctx) }()
	defer func() {
		stop()
		if err := recorder.Close(context.Background()); err != nil {
			t.Error(err)
		}
		<-finished
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		verdicts, err := mixed.Verify(ctx, []buffer.Entry{old, newEntry, pendingEntry})
		if err == nil && len(verdicts) == 3 && verdicts[0] == sealer.Sealed && verdicts[1] == sealer.Sealed && verdicts[2] == sealer.Sealed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mixed retained recovery timeout", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var count int
	if err = x.owner.QueryRow(ctx, `SELECT count(*) FROM ops_activity_v1.qualified_logs WHERE activity_run_id=$1::uuid`, mixed.Binding().RunID).Scan(&count); err != nil || count != 3 {
		t.Fatal("mixed recovery duplicate/missing", count, err)
	}
	if err = x.owner.QueryRow(ctx, `SELECT request_params FROM ops_activity_v1.qualified_logs WHERE activity_run_id=$1::uuid AND activity_ordinal=2`, mixed.Binding().RunID).Scan(&unchanged); err != nil {
		t.Fatal(err)
	}
	decoded, err := a.DecodeEnvelope([]byte(unchanged))
	if err != nil || decoded.Version != 2 || decoded.Reason != r.SenderNotLinked {
		t.Fatal("retained reason lost", err)
	}
	if err = s.DowngradeTo005(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); err == nil {
		t.Fatal("v2 rollback floor lost")
	}
	// Prove that all ordinary SQL fields, payload b/o/q and uniqueness are
	// aligned before testing only the reason/version guard. Every attempt rolls
	// back, so neither a successful control nor a rejection changes history.
	candidate := decoded
	candidate.RecordID = uuid.NewString()
	candidate.Ordinal = "102"
	candidate.BufferSeq = strconv.FormatUint(newEntry.Seq+100, 10)
	positive, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(positive)
	query := `INSERT INTO public.access_logs(id,external_id,method,status_code,ip_address,created_at,correlation_id,request_params,entry_hash,response_status,hash_format_version,buffer_seq,chain_name,org_id,activity_run_id,activity_producer_id,activity_kind,activity_ordinal,activity_observed_us,activity_record_id,activity_outcome) SELECT nextval('public.access_logs_id_seq'),external_id,method,status_code,ip_address,created_at,$6::text,$2,$3,response_status,hash_format_version,$4,chain_name,org_id,activity_run_id,activity_producer_id,activity_kind,$5,activity_observed_us,($6::text)::uuid,activity_outcome FROM public.access_logs WHERE activity_run_id=$1::uuid AND activity_ordinal=2`
	insertRolledBack := func(body []byte) error {
		t.Helper()
		tx, err := x.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tag, insertErr := tx.Exec(ctx, query, mixed.Binding().RunID, string(body), hex.EncodeToString(hash[:]), int64(newEntry.Seq+100), int64(102), candidate.RecordID)
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if insertErr == nil && tag.RowsAffected() != 1 {
			t.Fatal("guard control did not insert one row")
		}
		return insertErr
	}
	if err := insertRolledBack(positive); err != nil {
		t.Fatal("fully aligned v2 SQL control", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown":             func(e map[string]any) { e["c"] = "unknown" },
		"wrong outcome":       func(e map[string]any) { e["c"] = "request_cancelled" },
		"missing":             func(e map[string]any) { delete(e, "c") },
		"null":                func(e map[string]any) { e["c"] = nil },
		"v1 reason forbidden": func(e map[string]any) { e["v"] = 1 },
		"future version":      func(e map[string]any) { e["v"] = 3 },
	} {
		var envelope map[string]any
		if err := json.Unmarshal(positive, &envelope); err != nil {
			t.Fatal(err)
		}
		mutate(envelope)
		body, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := insertRolledBack(body); sqlState(err) != "P0001" {
			t.Fatal("isolated SQL reason guard", name, err)
		}
	}

	check()
}
