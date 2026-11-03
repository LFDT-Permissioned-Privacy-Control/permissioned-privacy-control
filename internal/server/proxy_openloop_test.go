package server

import (
	"context"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"privacy-proxy/internal/db"
)

// HISTORICAL DIAGNOSTIC, NOT GATE 2. This drives JSONRPCProcessor.Process
// directly: no HTTP, real auth, sealer, publisher, reconciler or compliance
// configuration. Its RD-1112 numbers are history. Throughput gate 2 uses the
// full-server runner in internal/perfgate (plan RD-1410 §9.5).
//
// OPEN-LOOP LOAD TEST (RD-1112). Unlike the closed-loop benchmark
// (proxy_throughput_bench_test.go), which holds a fixed number of requests in
// flight and measures the completion rate, this injects requests at a FIXED
// OFFERED RATE (default 5,000/sec) regardless of whether prior requests have
// finished — the real "can we sustain 5K TPS?" question. It reports achieved
// throughput and p50/p99/max latency, so you can see whether the proxy keeps up
// (achieved ≈ offered, bounded latency) or saturates (achieved < offered,
// latency climbs).
//
// The Ethereum node is mocked (instant, zero EVM), so this measures ONLY the
// Open Privacy Suite. Load is spread across many users (default 100) so the
// per-user MAX_CONCURRENT_REQUESTS cap (50) does not reject under aggregate
// load — mirroring production, where 5K TPS comes from many users, not one.
//
// Gated: runs only when BOTH PROXY_BENCH_DSN (a real migrated Postgres, Linux
// in CI) and PROXY_LOADTEST=1 are set, so it stays out of the normal unit
// suite. Tunables: PROXY_LOADTEST_RATE (req/sec), PROXY_LOADTEST_SECS,
// PROXY_LOADTEST_USERS, PROXY_LOADTEST_AUDIT (async|sync), PROXY_LOADTEST_MODE
// (legacy|v2: the legacy forwarding path or the V2 node-execution path against
// the gate-2 mock private node) and PROXY_LOADTEST_WORKLOAD (historical, the
// default for legacy: one transfer per user re-sent; unique, the default for
// v2: unique transfers; the legacy-vs-V2 comparison uses unique for both). See
// proxy_rd1112_paths_test.go.
//
//	PROXY_BENCH_DSN=postgres://... TEST_DATABASE_URL=postgres://... PROXY_LOADTEST=1 \
//	  go test -run TestProxyOpenLoop -timeout 300s -v ./internal/server/
func openLoopEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

type openLoopResult struct {
	offered     int
	total       int
	ok          int
	rejected429 int
	otherStatus int
	elapsed     time.Duration
	p50, p99    time.Duration
	max         time.Duration
}

func (r openLoopResult) achievedTPS() float64 {
	if r.elapsed <= 0 {
		return 0
	}
	return float64(r.ok) / r.elapsed.Seconds()
}

// runOpenLoop injects offeredRate×durSecs requests at offeredRate, request i
// being reqs[i % len(reqs)], one goroutine per request calling the processor
// in process (its node calls still go over loopback to the mocks, whose
// connection counts the harness checks), and returns latency stats over the
// successful requests.
func runOpenLoop(ctx context.Context, proc *JSONRPCProcessor, reqs []*ProcessRequest, offeredRate, durSecs int) openLoopResult {
	total := offeredRate * durSecs
	interval := time.Second / time.Duration(offeredRate)
	latencies := make([]time.Duration, total)
	statuses := make([]int, total)

	var wg sync.WaitGroup
	wg.Add(total)
	start := time.Now()
	for i := 0; i < total; i++ {
		// Catch-up pacer: schedule each request at start + i*interval. If the
		// dispatch loop falls behind, time.Until is negative and we fire
		// immediately, so the offered rate self-corrects rather than drifting.
		target := start.Add(time.Duration(i) * interval)
		if d := time.Until(target); d > 0 {
			time.Sleep(d)
		}
		go func(idx int, scheduled time.Time) {
			defer wg.Done()
			res := proc.Process(ctx, reqs[idx%len(reqs)])
			code := res.StatusCode
			if res.Error != nil {
				code = res.Error.StatusCode
			}
			// Latency is measured from the SCHEDULED send time, so any
			// dispatch backlog (the proxy not keeping up) shows up as latency.
			latencies[idx] = time.Since(scheduled)
			statuses[idx] = code
		}(i, target)
	}
	wg.Wait()
	elapsed := time.Since(start)

	okLat := make([]time.Duration, 0, total)
	res := openLoopResult{offered: offeredRate, total: total, elapsed: elapsed}
	for i := 0; i < total; i++ {
		switch statuses[i] {
		case http.StatusOK:
			res.ok++
			okLat = append(okLat, latencies[i])
		case http.StatusTooManyRequests:
			res.rejected429++
		default:
			res.otherStatus++
		}
	}
	sort.Slice(okLat, func(a, b int) bool { return okLat[a] < okLat[b] })
	res.p50 = pctl(okLat, 50)
	res.p99 = pctl(okLat, 99)
	if len(okLat) > 0 {
		res.max = okLat[len(okLat)-1]
	}
	return res
}

func pctl(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := p * len(sorted) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func TestProxyOpenLoop(t *testing.T) {
	if os.Getenv("PROXY_BENCH_DSN") == "" || os.Getenv("PROXY_LOADTEST") == "" {
		t.Skip("set PROXY_BENCH_DSN (real Postgres) and PROXY_LOADTEST=1 to run the open-loop 5K load test")
	}
	dsn := os.Getenv("PROXY_BENCH_DSN")
	rate := openLoopEnvInt("PROXY_LOADTEST_RATE", 5000)
	durSecs := openLoopEnvInt("PROXY_LOADTEST_SECS", 5)
	numUsers := openLoopEnvInt("PROXY_LOADTEST_USERS", 100)
	async := os.Getenv("PROXY_LOADTEST_AUDIT") != "sync"
	path := parseRD1112Path(t, os.Getenv("PROXY_LOADTEST_MODE"))

	database, err := db.New(dsn)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("reset: %v", err)
	}
	ctx := context.Background()

	workload := parseRD1112Workload(t, path, os.Getenv("PROXY_LOADTEST_WORKLOAD"))
	h := newRD1112Harness(t, database, path, numUsers, async)
	defer h.Close()
	warm, reqs := h.requests(t, workload, rate*durSecs)
	proc := h.Proc
	auditMode := "async"
	if !async {
		auditMode = "sync"
	}

	// Warm the perms cache + create each user's system-link row, so the
	// measured run is steady-state (not paying first-touch costs).
	h.warm(t, warm)

	res := runOpenLoop(ctx, proc, reqs, rate, durSecs)
	nodeConns := h.checkConnections(t)

	t.Logf("OPEN-LOOP (%s path, %s workload, %s audit, node mocked, %d users, node connections opened/pool: %s; historical RD-1112 legacy: 4,997/s at 5,000/s, Linux): offered=%d/s for %ds → "+
		"achieved=%.0f/s (%d ok, %d rejected-429, %d other) in %s | latency p50=%s p99=%s max=%s",
		path, workload, auditMode, numUsers, nodeConns, rate, durSecs, res.achievedTPS(),
		res.ok, res.rejected429, res.otherStatus, res.elapsed.Round(time.Millisecond),
		res.p50.Round(time.Microsecond), res.p99.Round(time.Microsecond), res.max.Round(time.Microsecond))

	if async {
		// Async path MUST hold the offered rate with bounded latency.
		if res.achievedTPS() < 0.90*float64(rate) {
			t.Errorf("async did not hold offered rate: achieved %.0f/s < 90%% of offered %d/s", res.achievedTPS(), rate)
		}
		if res.rejected429 > 0 {
			t.Errorf("async path rejected %d requests with 429 — proxy could not keep up at %d/s", res.rejected429, rate)
		}
		if res.otherStatus > 0 {
			t.Errorf("async path returned %d non-200/429 responses", res.otherStatus)
		}
		// Generous ceiling for a shared CI/Docker host; the point is "bounded",
		// not a hard SLA number. Tune via the assertion if your CI is faster.
		if res.p99 > 500*time.Millisecond {
			t.Errorf("async p99 latency %s exceeds 500ms at %d/s — investigate saturation", res.p99, rate)
		}
	} else {
		// Sync path is expected to SATURATE well below the offered rate — it
		// documents the bottleneck RD-1112 removes. (Report-only contrast.)
		if res.achievedTPS() >= 0.80*float64(rate) {
			t.Logf("NOTE: sync audit unexpectedly kept up (%.0f/s) — the chain-mutex bottleneck may have changed", res.achievedTPS())
		}
	}
}
