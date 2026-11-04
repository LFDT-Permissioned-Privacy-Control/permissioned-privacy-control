package perfgate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(t *testing.T, key string, fallback int) int {
	v, err := strconv.Atoi(envOr(key, strconv.Itoa(fallback)))
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return v
}

func envDuration(t *testing.T, key string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(envOr(key, fallback.String()))
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return v
}

// q6FromEnv reads the optional concurrent Q6 prototype (OPS_GATE2_Q6=a|b),
// or the standalone one (OPS_Q6=1, OPS_Q6_VARIANT=a|b).
func q6FromEnv(t *testing.T) *Q6Config {
	variant := os.Getenv("OPS_GATE2_Q6")
	if variant == "" {
		if os.Getenv("OPS_Q6") != "1" {
			return nil
		}
		variant = os.Getenv("OPS_Q6_VARIANT")
	}
	if variant != "a" && variant != "b" {
		t.Fatalf("Q6 variant must be a or b, got %q", variant)
	}
	return &Q6Config{Variant: variant, Instances: envInt(t, "OPS_Q6_INSTANCES", 2), Rate: envInt(t, "OPS_Q6_RATE", 5250), Drain: envDuration(t, "OPS_Q6_DRAIN", 90*time.Second),
		MaxBatch: envInt(t, "OPS_Q6_MAX_BATCH", 1024), QueueCap: envInt(t, "OPS_Q6_QUEUE_CAP", 50_000), ClaimFraction: envFloat(t, "OPS_Q6_CLAIM_FRACTION", 0.1),
		RetryFraction: envFloat(t, "OPS_Q6_RETRY_FRACTION", 0.01), ConflictFrac: envFloat(t, "OPS_Q6_CONFLICT_FRACTION", 0.001), AuditRate: envInt(t, "OPS_Q6_AUDIT_RATE", 10_500),
		Senders: envInt(t, "OPS_Q6_SENDERS", 1000)}
}

func envFloat(t *testing.T, key string, fallback float64) float64 {
	v, err := strconv.ParseFloat(envOr(key, strconv.FormatFloat(fallback, 'f', -1, 64)), 64)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return v
}

// TestQ6Standalone runs the Q6 prototype alone on its own Postgres instance
// and mock node (the upper bound without server load).
func TestQ6Standalone(t *testing.T) {
	if os.Getenv("OPS_Q6") != "1" {
		t.Skip("set OPS_Q6=1, OPS_Q6_VARIANT=a|b and OPS_Q6_OUTPUT to run the tracking-write prototype")
	}
	output := os.Getenv("OPS_Q6_OUTPUT")
	if output == "" {
		t.Fatal("OPS_Q6_OUTPUT is required")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if free := freeGiB(output); free >= 0 && free < 15 {
		t.Fatalf("only %.1f GiB free", free)
	}
	ctx := context.Background()
	cfg := q6FromEnv(t)
	lag := envDuration(t, "OPS_GATE2_FINALITY_LAG", time.Second)
	cfg.Warmup, cfg.Window, cfg.FinalityLag = envDuration(t, "OPS_GATE2_WARMUP", lag+30*time.Second), envDuration(t, "OPS_GATE2_WINDOW", 60*time.Second), lag
	// The tracking database has its own instance; main (claims) and audit
	// (synthetic sealer load) share a second one, so the tracking figures
	// are not mixed with their WAL and CPU.
	suffix := randomHex(4)
	pg, err := StartPostgres(ctx, "perfgate-q6-tracking-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Remove(context.Background())
	other, err := StartPostgres(ctx, "perfgate-q6-main-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Remove(context.Background())
	for _, stmt := range []string{"CREATE DATABASE tracking", "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"} {
		if _, err := pg.Psql(ctx, "postgres", stmt); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []string{"CREATE DATABASE main", "CREATE DATABASE audit"} {
		if _, err := other.Psql(ctx, "postgres", stmt); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := OpenDB(pg.DSN("postgres", "postgres", pg.Password))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	node := MockNodeConfig{ChainID: 31337, DeploymentID: "perfgate-q6", PrivateToken: "perfgate-private-" + randomHex(16), BlockTime: time.Second, FinalityLag: lag, Latency: envDuration(t, "OPS_GATE2_LATENCY", time.Millisecond)}
	proc, err := StartMockProcess(ctx, node, output, envInt(t, "OPS_GATE2_MOCK_GOMAXPROCS", 3))
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	cfg.ExecDSN, cfg.MainDSN, cfg.AuditDSN = pg.DSN("tracking", "postgres", pg.Password), other.DSN("main", "postgres", other.Password), other.DSN("audit", "postgres", other.Password)
	cfg.NodeURL, cfg.NodeToken, cfg.DeploymentID, cfg.Index, cfg.NodeStats = proc.PrivateURL, node.PrivateToken, node.DeploymentID, proc.Index, proc.Stats
	cfg.ExecAdmin, cfg.ExecContainer, cfg.Layout = admin, &pg.Container, envOr("OPS_Q6_LAYOUT", "standalone_one_instance")
	run, err := PrepareQ6(ctx, *cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	start := time.Now().Add(2 * time.Second)
	phases := Phases{Start: start, WindowStart: start.Add(cfg.Warmup), WindowEnd: start.Add(cfg.Warmup + cfg.Window)}
	report, err := run.Run(ctx, phases, proc.Stamps)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(map[string]any{"machine_start": machineInfo(output), "q6": report}, "", "  ")
	if err := os.WriteFile(filepath.Join(output, "q6-report.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if !report.QuotaConsistent {
		t.Errorf("pending_quota.used != count(pending rows) at the end")
	}
	t.Logf("q6 %s: %.0f rows/s committed in window, %.0f commits/s, mean batch %.1f, commit wait p50/p99 %.2f/%.2f ms, request p99 %d ms, rejections %d, quota consistent %v",
		cfg.Variant, report.CommittedPerSec, report.CommitsPerSec, report.BatchSizeMean, report.CommitWaitMS.P50, report.CommitWaitMS.P99, report.Window.LatencyMS.P99, report.Window.Phase["window"].Rejected, report.QuotaConsistent)
}

// extraEnv parses "K=V,K2=V2" server overrides for labelled sensitivity runs.
func extraEnv(spec string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		if k, v, ok := strings.Cut(pair, "="); ok && k != "" {
			out[k] = v
		}
	}
	return out
}

// TestMockNodeProcessMain is the mock-node subprocess entry point used by
// StartMockProcess. It does nothing in a normal test run.
func TestMockNodeProcessMain(t *testing.T) {
	config := os.Getenv("OPS_GATE2_MOCK_CONFIG")
	if config == "" {
		t.Skip("mock node subprocess entry point")
	}
	if err := ServeMockProcess(config, os.Getenv("OPS_GATE2_MOCK_READY")); err != nil {
		t.Fatal(err)
	}
}

// TestGate2 runs one gate-2 case (plan §9.5) against a real OPS binary. It
// never runs in CI: it needs OPS_GATE2=1, docker and a built server binary.
//
//	go build -tags mockauth -o /tmp/ops ./cmd/server
//	OPS_GATE2=1 OPS_GATE2_SERVER=/tmp/ops OPS_GATE2_MODE=legacy \
//	  OPS_GATE2_OUTPUT=/tmp/gate2/legacy-open go test ./internal/perfgate -run TestGate2 -v -timeout 60m
func TestGate2(t *testing.T) {
	if os.Getenv("OPS_GATE2") != "1" {
		t.Skip("set OPS_GATE2=1, OPS_GATE2_SERVER and OPS_GATE2_OUTPUT to run the gate-2 full-server runner")
	}
	// P7's approved execution floor is 12 GiB; retain the more conservative
	// default unless an explicit, recorded diagnostic setting selects it.
	minFreeGiB := envInt(t, "OPS_GATE2_MIN_FREE_GIB", 15)
	if minFreeGiB < 12 {
		t.Fatal("OPS_GATE2_MIN_FREE_GIB must be an integer of at least 12 (the approved P7 disk floor)")
	}
	output := os.Getenv("OPS_GATE2_OUTPUT")
	if output == "" || os.Getenv("OPS_GATE2_SERVER") == "" {
		t.Fatal("OPS_GATE2_SERVER and OPS_GATE2_OUTPUT are required")
	}
	if _, err := os.Stat(output); err == nil {
		t.Fatalf("%s exists; use a new output directory per run", output)
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		t.Fatal(err)
	}
	lag := envDuration(t, "OPS_GATE2_FINALITY_LAG", time.Second)
	warmup := envDuration(t, "OPS_GATE2_WARMUP", lag+30*time.Second)
	if warmup < lag+30*time.Second && os.Getenv("OPS_GATE2_SMOKE") != "1" {
		t.Fatalf("warm-up %s is shorter than finality lag + 30 s (plan §9.5)", warmup)
	}
	loop := envOr("OPS_GATE2_LOOP", "open")
	// R12.1: the closed loop is a sweep (default 32, 128, 256 in flight), one
	// independent case with a fresh stack per concurrency.
	concurrencies := []int{0} // the open loop has no fixed concurrency
	if loop == "closed" {
		var err error
		if concurrencies, err = parseConcurrencies(envOr("OPS_GATE2_CONCURRENCY", "32,128,256")); err != nil {
			t.Fatal(err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for _, concurrency := range concurrencies {
		if ctx.Err() != nil {
			t.Fatal("interrupted: remaining sweep cases skipped")
		}
		dir, name := output, envOr("OPS_GATE2_NAME", filepath.Base(output))
		if len(concurrencies) > 1 {
			dir, name = filepath.Join(output, "c"+strconv.Itoa(concurrency)), name+"-c"+strconv.Itoa(concurrency)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		config := Gate2Config{
			Name:        name,
			Binary:      os.Getenv("OPS_GATE2_SERVER"),
			Mode:        envOr("OPS_GATE2_MODE", "legacy"),
			Loop:        loop,
			Rate:        envInt(t, "OPS_GATE2_RATE", 5250),
			Concurrency: concurrency,
			Connections: envInt(t, "OPS_GATE2_CONNECTIONS", 0),
			Warmup:      warmup,
			Window:      envDuration(t, "OPS_GATE2_WINDOW", 60*time.Second),
			Drain:       envDuration(t, "OPS_GATE2_DRAIN", 60*time.Second),
			Latency:     envDuration(t, "OPS_GATE2_LATENCY", time.Millisecond),
			FinalityLag: lag,
			Users:       envInt(t, "OPS_GATE2_USERS", 100),
			PerUser:     envInt(t, "OPS_GATE2_WALLETS_PER_USER", 10),
			SeparateDB:  os.Getenv("OPS_GATE2_SEPARATE_TRACKING_DB") == "1",
			MockProcs:   envInt(t, "OPS_GATE2_MOCK_GOMAXPROCS", 3),
			ExtraEnv:    extraEnv(os.Getenv("OPS_GATE2_EXTRA_ENV")),
			Q6:          q6FromEnv(t),
			Dir:         dir,
			MinFreeGiB:  float64(minFreeGiB),
			Log:         t.Logf,
		}
		if len(concurrencies) == 1 {
			runGate2Case(ctx, t, config)
			continue
		}
		// One subtest per case, so a failed case does not skip the rest.
		t.Run(name, func(t *testing.T) {
			config.Log = t.Logf
			runGate2Case(ctx, t, config)
		})
	}
}

func runGate2Case(ctx context.Context, t *testing.T, config Gate2Config) {
	report, err := RunGate2(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(filepath.Join(config.Dir, "gate2-report.json"), report); err != nil {
		t.Fatal(err)
	}
	w := report.Window
	if report.Aborted != "" {
		t.Errorf("run aborted: %s", report.Aborted)
	}
	if !w.Valid {
		t.Errorf("%s: %s", config.Name, w.InvalidReason)
	}
	for _, note := range report.Errors {
		t.Logf("%s: %s", config.Name, note)
	}
	t.Logf("%s %s/%s: achieved %.1f/s in the %.0f s window (%d completed), rejected in window %d, runner transport errors %d, connections opened %d (pool %d), latency p50/p99/max %d/%d/%d ms",
		config.Name, config.Mode, config.Loop, w.AchievedPerSecond, w.WindowSeconds, w.CompletedInWindow, w.Phase["window"].Rejected, w.RunnerTransportErrors, w.ConnectionsOpened, report.Config.Connections, w.LatencyMS.P50, w.LatencyMS.P99, w.LatencyMS.Max)
}

// parseConcurrencies reads a comma-separated list of positive in-flight counts.
func parseConcurrencies(spec string) ([]int, error) {
	var out []int
	for _, field := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("OPS_GATE2_CONCURRENCY: %q is not a positive integer list", spec)
		}
		out = append(out, n)
	}
	return out, nil
}

func TestParseConcurrenciesAndOpenLoopPool(t *testing.T) {
	got, err := parseConcurrencies("32, 128,256")
	if err != nil || len(got) != 3 || got[0] != 32 || got[1] != 128 || got[2] != 256 {
		t.Fatalf("sweep %v %v", got, err)
	}
	if _, err := parseConcurrencies("32,0"); err == nil {
		t.Fatal("a zero concurrency must be refused")
	}
	for rate, want := range map[int]int{100: 64, 5250: 1313, 50_000: 4096} {
		if got := OpenLoopConnections(rate); got != want {
			t.Fatalf("pool for %d/s = %d, want %d", rate, got, want)
		}
	}
}
