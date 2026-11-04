package db_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/db"
)

// The buffer and the audit database agree on the width of an allocation range.
func TestBufferRangeShiftMatches(t *testing.T) {
	if db.BufferRangeShift != buffer.RangeShift {
		t.Fatalf("db.BufferRangeShift %d != buffer.RangeShift %d", db.BufferRangeShift, buffer.RangeShift)
	}
}

// audit/004 (RD-1410): ranges are drawn from a sequence the runtime role may
// draw from but not set, start above every stored buffer sequence and never
// repeat.
func TestAccessLogBufferRangesAreDrawnNotSet(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	var usage, update bool
	if err := database.Conn().QueryRowContext(ctx, `SELECT has_sequence_privilege('privacy_proxy_app', 'access_logs_buffer_range_seq', 'USAGE'),
		has_sequence_privilege('privacy_proxy_app', 'access_logs_buffer_range_seq', 'UPDATE')`).Scan(&usage, &update); err != nil {
		t.Fatal(err)
	}
	if !usage || update {
		t.Fatalf("privacy_proxy_app: USAGE %v UPDATE %v, want draw-only", usage, update)
	}
	first, err := database.ReserveAccessLogBufferRange(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := database.ReserveAccessLogBufferRange(ctx)
	if err != nil || second <= first {
		t.Fatalf("ranges %d then %d %v", first, second, err)
	}
	var stored int64
	if err := database.Conn().QueryRowContext(ctx, `SELECT COALESCE(MAX(buffer_seq), 0) FROM access_logs`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if first<<db.BufferRangeShift <= uint64(stored) {
		t.Fatalf("range %d starts at or below a stored buffer sequence %d", first, stored)
	}
}

// Finding 1 (fork) and finding 5: two writers of one chain — two instances
// sharing a chain name — seal concurrently, each with its own in-process
// chain head, and the stored chain still links: every batch links to the head
// read under the chain's lock.
func TestConcurrentWritersOfOneChainNeverFork(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	store := db.NewAuditHandle(database)
	name := "shared-" + uuid.NewString()[:8]
	const writers, batches, per = 2, 15, 10
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			chain := audit.NewHashChain("")
			base := uint64(10+w) << db.BufferRangeShift
			seq := base
			for b := 0; b < batches; b++ {
				records := make([]db.BufferedAccessLog, per)
				for i := range records {
					seq++
					records[i] = db.BufferedAccessLog{Seq: seq, Record: db.AccessLogRecord{ExternalID: fmt.Sprintf("did:test:w%d", w), Method: "eth_call", StatusCode: 200, CorrelationID: uuid.NewString()}}
				}
				if _, err := store.SealBufferedAccessLogs(ctx, chain, records, name); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	res, err := audit.NewVerifier(database.Conn(), database).Verify(ctx, audit.ChainAccessLogs)
	if err != nil || !res.OK || res.ScannedRows != writers*batches*per {
		t.Fatalf("shared chain: %+v %v", res, err)
	}
}

// The request-path fallback must serialize with buffered writers and read
// the stored head under the same lock, even when its cached head is stale.
func TestSynchronousFallbackAndBufferedWriterShareChainLock(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	buffered, fallback := audit.NewHashChain(""), audit.NewHashChain("")
	base := uint64(100) << db.BufferRangeShift
	for i := 0; i < 5; i++ {
		rec := db.AccessLogRecord{ExternalID: "did:test:buffered", Method: "eth_call", StatusCode: 200}
		if _, err := database.SealBufferedAccessLog(ctx, buffered, rec, base+uint64(i)+1, "access_logs"); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := database.LogAccessChained(ctx, fallback, "did:test:fallback", "eth_call", 200, "127.0.0.1", "", nil, nil, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	res, err := audit.NewVerifier(database.Conn(), database).Verify(ctx, audit.ChainAccessLogs)
	if err != nil || !res.OK || res.ScannedRows != 10 {
		t.Fatalf("mixed buffered/fallback chain: %+v error=%v", res, err)
	}
}

func TestSynchronousFallbackPreservesConfiguredChain(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	name := "instance-chain"
	store := db.NewAuditHandleForChain(database, name)
	if _, err := store.SealBufferedAccessLog(ctx, audit.NewHashChain(""), db.AccessLogRecord{
		ExternalID: "did:test:buffered", Method: "eth_call", StatusCode: 200,
	}, uint64(101)<<db.BufferRangeShift, name); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.LogAccessChained(ctx, audit.NewHashChain(""), "did:test:fallback", "eth_call", 200, "127.0.0.1", "", nil, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	var named, other int
	if err := database.Conn().QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE chain_name=$1), count(*) FILTER (WHERE chain_name<>$1) FROM access_logs`, name).Scan(&named, &other); err != nil || named != 2 || other != 0 {
		t.Fatalf("configured chain: named=%d other=%d error=%v", named, other, err)
	}
	res, err := audit.NewVerifier(database.Conn(), database).Verify(ctx, audit.ChainAccessLogs)
	if err != nil || !res.OK || res.ScannedRows != 2 {
		t.Fatalf("custom buffered/fallback chain: %+v error=%v", res, err)
	}
}
