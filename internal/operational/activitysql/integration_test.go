package activitysql_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/networkidentity"
	s "privacy-proxy/internal/operational/activitysql"
)

type database struct {
	owner                          *pgx.Conn
	dsn, writer, reader, retention string
	registration                   s.Registration
	scope                          s.Scope
}

func setupDatabase(t *testing.T) *database {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if raw, err := exec.CommandContext(ctx, "docker", "image", "inspect", "postgres:16-alpine").CombinedOutput(); err != nil {
		t.Fatalf("cached owned PostgreSQL required: %v %s", err, raw)
	}
	name := "ops-v2-activity-test-" + uuid.NewString()[:8]
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--memory", "256m", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=activity-public-test-only", "--env", "POSTGRES_DB=activity_test", "--name", name, "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("owned PostgreSQL: %v %s", err, raw)
	}
	id := strings.TrimSpace(string(raw))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if raw, err := exec.CommandContext(ctx, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Errorf("owned fixture cleanup: %v %s", err, raw)
		}
	})
	raw, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	x := &database{dsn: "postgres://postgres:activity-public-test-only@" + strings.TrimSpace(string(raw)) + "/activity_test?sslmode=disable"}
	for ctx.Err() == nil {
		x.owner, err = pgx.Connect(ctx, x.dsn)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("owned PostgreSQL readiness", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = x.owner.Close(ctx)
	})
	for _, role := range []string{"b1_writer", "b1_reader", "b1_retention"} {
		if _, err := x.owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN NOINHERIT PASSWORD 'activity-public-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := filepath.Glob("../../db/migrations_audit/00[1-4]_*.sql")
	if err != nil || len(paths) != 4 {
		t.Fatal("baseline SQL", paths, err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.owner.Exec(ctx, "BEGIN;"+string(raw)+";COMMIT"); err != nil {
			t.Fatal("exact baseline", path, err)
		}
	}
	if err := s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); err != nil {
		t.Fatal("activity005 migrate", err)
	}
	u, _ := url.Parse(x.dsn)
	u.User = url.UserPassword("b1_writer", "activity-public-test-only")
	x.writer = u.String()
	u.User = url.UserPassword("b1_reader", "activity-public-test-only")
	x.reader = u.String()
	u.User = url.UserPassword("b1_retention", "activity-public-test-only")
	x.retention = u.String()
	x.registration = s.Registration{Network: networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "activity-test"}, SourceID: uuid.NewString(), Configuration: [32]byte{1}, Limits: s.DefaultStorageLimits(), Roles: s.RoleNames{"b1_writer", "b1_reader", "b1_retention"}}
	if err := s.Initialize(ctx, x.dsn, x.registration, true); err != nil {
		t.Fatal("initialize", err)
	}
	key, _ := x.registration.Network.Key()
	status, err := s.Status(ctx, x.dsn, key, x.registration.SourceID)
	if err != nil {
		t.Fatal("status", err)
	}
	x.scope = s.Scope{key, x.registration.SourceID, status.Metadata.Generation}
	return x
}
func testEntry(t *testing.T, b a.RunBinding, ordinal int64, observed int64) buffer.Entry {
	t.Helper()
	raw, err := os.ReadFile("../../activitylog/testdata/normal-envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	var e a.Envelope
	if json.Unmarshal(raw, &e) != nil {
		t.Fatal("fixture")
	}
	e.Network = hexDigest(b.Metadata.NetworkKey)
	e.Generation = b.Metadata.Generation
	e.Configuration = hexDigest(b.Metadata.Configuration)
	e.ProducerID = b.ProducerID
	e.RunID = b.RunID
	e.RecordID = uuid.NewString()
	e.Ordinal = fmtDecimal(ordinal)
	e.ObservedMicros = observed
	e.BufferSeq = "1"
	sealed, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	spool := append([]byte{}, sealed[:len(sealed)-len(`,"b":"1"}`)]...)
	spool = append(spool, '}')
	if _, err := a.DecodeSpool(spool); err != nil {
		t.Fatalf("generated public spool: %v %s", err, spool)
	}
	return buffer.Entry{Seq: b.Base + uint64(ordinal), Data: spool}
}
func hexDigest(d a.Digest) string { return hex.EncodeToString(d[:]) }
func fmtDecimal(n int64) string   { return strconv.FormatInt(n, 10) }

func TestRestrictedWriterSealPruneAndPreservedOrphan(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	w, err := s.OpenWriter(ctx, x.writer, x.scope)
	if err != nil {
		t.Fatal("writer", err)
	}
	defer w.Close()
	run, err := w.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal("start", err)
	}
	entries := []buffer.Entry{testEntry(t, run.Binding(), 1, 1000000), testEntry(t, run.Binding(), 2, 3000000), testEntry(t, run.Binding(), 3, 2000000)}
	if err := run.SealBatch(ctx, entries); err != nil {
		t.Fatal("seal", err)
	}
	if err := run.SealBatch(ctx, entries); err != nil {
		t.Fatal("idempotent", err)
	}
	foreign := testEntry(t, run.Binding(), 1, 1000000)
	if verdicts, err := run.Verify(ctx, []buffer.Entry{foreign}); err != nil || len(verdicts) != 1 || verdicts[0] != sealer.Foreign {
		t.Fatal("different canonical UUID/body not foreign", verdicts, err)
	}
	if err := run.SealOne(ctx, foreign.Seq, foreign.Data); !errors.Is(err, sealer.ErrChainAhead) {
		t.Fatal("foreign seal was overwritten", err)
	}
	verifyChain := func(expected int64) {
		config, err := pgx.ParseConfig(x.dsn)
		if err != nil {
			t.Fatal(err)
		}
		db := stdlib.OpenDB(*config)
		defer db.Close()
		result, err := audit.NewVerifier(db, nil).Verify(ctx, audit.ChainAccessLogs)
		if err != nil || !result.OK || result.ScannedRows != expected {
			t.Fatal("existing actual format2 verifier", result, err)
		}
	}
	verifyChain(3)
	v, err := run.Verify(ctx, entries)
	if err != nil || len(v) != 3 || v[0] != sealer.Sealed || v[2] != sealer.Sealed {
		t.Fatal("verify", v, err)
	}
	status, err := s.Status(ctx, x.dsn, x.scope.NetworkKey, x.scope.SourceID)
	if err != nil || status.Rows != 3 {
		t.Fatal("counter", status, err)
	}
	r, err := s.OpenRetention(ctx, x.retention, x.scope)
	if err != nil {
		t.Fatal("retention", err)
	}
	defer r.Close()
	reader, err := s.OpenReader(ctx, x.reader, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	beforePrune, err := reader.Open(ctx, "", 1000000)
	if err != nil {
		t.Fatal(err)
	}
	beforePrune.Close()
	if n, err := r.Prune(ctx, 2500000, 5000); err != nil || n != 1 {
		t.Fatal("prefix only", n, err)
	}
	if err := beforePrune.CheckCurrent(ctx); err == nil {
		t.Fatal("old case period remained eligible after floor crossed it")
	}
	if _, err := run.Verify(ctx, entries[:1]); !errors.Is(err, a.ErrQuarantined) {
		t.Fatal("pruned crash orphan must be preserved", err)
	}
	if n, err := r.Prune(ctx, 1000000, 5000); err != nil || n != 0 {
		t.Fatal("stale lower floor", n, err)
	}
	status, err = s.Status(ctx, x.dsn, x.scope.NetworkKey, x.scope.SourceID)
	if err != nil || status.RetainedFromMicros != 2500000 || status.Rows != 2 || status.Runs != 1 {
		t.Fatal("monotone retained state", status, err)
	}
	if n, err := r.Prune(ctx, 4000000, 5000); err != nil || n != 2 {
		t.Fatal("full prune", n, err)
	}
	if err := run.SealOne(ctx, entries[2].Seq+1, testEntry(t, run.Binding(), 4, 5000000).Data); err != nil {
		t.Fatal("trusted head continuity after full prune", err)
	}
	verifyChain(1)
}
