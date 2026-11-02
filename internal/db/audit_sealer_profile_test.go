package db_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
)

// TestAuditSealerProfile is a P0 profile (plan RD-1410 §6, Codex 3.9): the
// inherited single sealer under the real event mix — one request record plus
// one ops.system.finalized system record per transaction (§4.8.6, §6.1) —
// with the production seal function (SealBufferedAccessLog, one INSERT per
// record) and the production defaults (500 per 1 s tick). Gated:
// OPS_P0_PROFILE=1. The Pebble buffer lives on the host disk.
func TestAuditSealerProfile(t *testing.T) {
	if os.Getenv("OPS_P0_PROFILE") != "1" {
		t.Skip("set OPS_P0_PROFILE=1 to run the audit sealer profile")
	}
	ctx := context.Background()
	// Each case gets its own audit database: buffer_seq is unique across
	// access_logs, and every fresh buffer starts its sequence at 1.
	newChain := func(chainName string) (sealer.SealFunc, sealer.HighWaterFunc) {
		dsn, cleanup := db.SetupTestContainer(t)
		t.Cleanup(cleanup)
		database, err := db.New(dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { database.Close() })
		if err := db.EnsureAuditSchemaForTest(database); err != nil {
			t.Fatal(err)
		}
		auditDB := db.NewAuditHandle(database)
		seed, err := auditDB.GetLatestAccessLogHashForChain(ctx, chainName)
		if err != nil {
			t.Fatal(err)
		}
		chain := audit.NewHashChain(seed)
		seal := func(ctx context.Context, seq uint64, data []byte) error {
			var rec db.AccessLogRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Errorf("corrupt profile record %d: %v", seq, err)
				return nil
			}
			_, err := auditDB.SealBufferedAccessLog(ctx, chain, rec, seq, chainName)
			return err
		}
		return seal, func(ctx context.Context) (uint64, error) { return auditDB.GetMaxAccessLogBufferSeq(ctx, chainName) }
	}
	// Records shaped like production: the request path's access-log record
	// (logAccess: no params by default, response status omitted when equal,
	// a unique correlation id per request, a few hundred principals) and the
	// §4.8.6 system event with its populated Params.
	record := func(i int) []byte {
		did := fmt.Sprintf("did:test:perf-user-%03d", i%300)
		correlation := fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i)
		if i%2 == 0 {
			data, _ := json.Marshal(db.AccessLogRecord{ExternalID: did, Method: "eth_sendRawTransaction", StatusCode: 200, IPAddress: "127.0.0.1", CorrelationID: correlation, OrgID: "11111111-1111-4111-8111-111111111111"})
			return data
		}
		data, _ := json.Marshal(db.AccessLogRecord{ExternalID: did, Method: "ops.system.finalized", StatusCode: 200, CorrelationID: correlation, OrgID: "11111111-1111-4111-8111-111111111111",
			Params: []byte(fmt.Sprintf(`{"tx_hash":"0x%064x","context_id":"%s","generation":1,"incarnation":"33333333-3333-4333-8333-333333333333","min_version":7,"expires_at":1800000000,"actor":"system:identity-renewal"}`, i, correlation))})
		return data
	}
	result := map[string]any{"record_bytes": map[string]int{"request": len(record(0)), "system": len(record(1))},
		"environment": "macOS host, Pebble buffer on the host disk (F_FULLFSYNC per Sync), audit Postgres alone in an OrbStack container: an upper bound for a shared server"}

	// 1. Seal capacity with no concurrent appends: drain a pre-filled buffer
	//    by repeated ticks at the default batch (500) and at 5,000.
	for _, batch := range []int{500, 5000} {
		buf, err := buffer.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		const prefilled = 20_000
		var wg sync.WaitGroup
		for w := 0; w < 32; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := w; i < prefilled; i += 32 {
					if _, err := buf.Append(record(i)); err != nil {
						t.Error(err)
						return
					}
				}
			}(w)
		}
		wg.Wait()
		seal, highWater := newChain(fmt.Sprintf("perf-capacity-%d", batch))
		s := sealer.New(buf, seal, highWater, sealer.Config{Batch: batch, Interval: time.Millisecond})
		start := time.Now()
		sealed := 0
		ticks := 0
		for sealed < prefilled {
			n, err := s.Tick(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				break
			}
			sealed += n
			ticks++
		}
		elapsed := time.Since(start)
		result[fmt.Sprintf("capacity_batch_%d", batch)] = map[string]any{"sealed": sealed, "ticks": ticks, "seconds": elapsed.Seconds(), "records_per_second_without_tick_sleep": float64(sealed) / elapsed.Seconds(),
			"tick_ms_mean": float64(elapsed.Milliseconds()) / float64(max(ticks, 1)), "records_per_second_with_default_1s_interval": float64(batch) / max(1, elapsed.Seconds()/float64(max(ticks, 1)))}
		_ = buf.Close()
	}

	// 2. The production configuration under the gate-2 event mix:
	//    2 records per transaction at 5,250 tx/s = 10,500 appends/s for 20 s.
	buf, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	runCtx, cancel := context.WithCancel(ctx)
	seal, highWater := newChain("perf-production")
	s := sealer.New(buf, seal, highWater, sealer.Config{})
	go s.Run(runCtx)
	var appended, appendErrors atomic.Int64
	var appendNS atomic.Int64
	const rate, seconds = 10_500, 20
	start := time.Now()
	var sealed5, sealed20 uint64
	var at5, at20 time.Time
	go func() {
		time.Sleep(time.Until(start.Add(5 * time.Second)))
		sealed5, _ = highWater(ctx)
		at5 = time.Now()
		time.Sleep(time.Until(start.Add(20 * time.Second)))
		sealed20, _ = highWater(ctx)
		at20 = time.Now()
	}()
	var wg sync.WaitGroup
	for i := 0; i < rate*seconds; i++ {
		at := start.Add(time.Duration(i) * time.Second / rate)
		if d := time.Until(at); d > 0 {
			time.Sleep(d)
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := record(i)
			began := time.Now()
			if _, err := buf.Append(data); err != nil {
				appendErrors.Add(1)
				return
			}
			appendNS.Add(time.Since(began).Nanoseconds())
			appended.Add(1)
		}(i)
	}
	wg.Wait()
	offered := time.Since(start)
	time.Sleep(time.Until(start.Add(20*time.Second + 100*time.Millisecond)))
	steady := float64(sealed20-sealed5) / at20.Sub(at5).Seconds()
	sealedAt, _ := highWater(ctx)
	pending, _ := buf.PendingCount()
	cancel()
	s.Wait()
	result["production_config_at_10500_per_second"] = map[string]any{"offered_seconds": offered.Seconds(), "appended": appended.Load(), "append_errors": appendErrors.Load(),
		"append_mean_us": float64(appendNS.Load()) / float64(max(appended.Load(), 1)) / 1e3, "sealed": sealedAt, "steady_seal_rate_per_second_5s_to_20s": steady,
		"pending_at_end": pending, "backlog_growth_per_second": float64(rate) - steady, "projected_drain_seconds_at_measured_rate": float64(pending) / max(steady, 1)}
	t.Logf("audit sealer profile: %+v", result)
	if out := os.Getenv("OPS_P0_OUTPUT"); out != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		_ = os.MkdirAll(out, 0o700)
		_ = os.WriteFile(filepath.Join(out, "audit-sealer-profile.json"), data, 0o600)
	}
}
