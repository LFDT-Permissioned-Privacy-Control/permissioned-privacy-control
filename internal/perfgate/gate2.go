package perfgate

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Gate2Config is one gate-2 case (plan §9.5).
type Gate2Config struct {
	Name        string            `json:"name"`
	Binary      string            `json:"binary"`
	Mode        string            `json:"mode"` // legacy | reth
	Loop        string            `json:"loop"` // open | closed
	Rate        int               `json:"rate"`
	Concurrency int               `json:"concurrency"`
	Connections int               `json:"connections"` // runner keep-alive pool = bound on requests in flight (see OpenLoopConnections)
	Warmup      time.Duration     `json:"warmup"`
	Window      time.Duration     `json:"window"`
	Drain       time.Duration     `json:"drain"`
	Latency     time.Duration     `json:"latency"`
	FinalityLag time.Duration     `json:"finality_lag"`
	Users       int               `json:"users"`
	PerUser     int               `json:"wallets_per_user"`
	SeparateDB  bool              `json:"separate_tracking_db"`
	MockProcs   int               `json:"mock_gomaxprocs"`
	ExtraEnv    map[string]string `json:"extra_env"`
	Dir         string            `json:"-"`
	MinFreeGiB  float64           `json:"min_free_gib"`
	// Q6, when set, runs the tracking-write prototype against this stack's
	// tracking database over the same phases (concurrent with the server load).
	Q6  *Q6Config                        `json:"q6,omitempty"`
	Log func(format string, args ...any) `json:"-"`
}

// Gate2Report is the per-case JSON report.
type Gate2Report struct {
	Config         Gate2Config                 `json:"config"`
	Machine        map[string]any              `json:"machine_start"`
	MachineEnd     map[string]any              `json:"machine_end"`
	Env            map[string]string           `json:"server_env"`
	Window         WindowReport                `json:"window"`
	Stages         map[string]Millis           `json:"stages_ms"`
	Clusters       map[string]ClusterDelta     `json:"db_window"`
	WriteStmts     map[string]map[string]int64 `json:"write_statements_window"`
	WaitEvents     map[string]int              `json:"wait_event_samples_window"`
	PerTx          map[string]float64          `json:"per_tx"`
	OPSCPUSeconds  float64                     `json:"ops_cpu_seconds_window"`
	MockCPUSeconds float64                     `json:"mock_cpu_seconds_window"`
	RunnerCPU      float64                     `json:"runner_cpu_seconds_window"`
	Statements     map[string][]Statement      `json:"top_statements"`
	ServerStages   map[string]HistogramSummary `json:"server_histograms"`
	ServerCounters map[string]float64          `json:"server_counter_deltas"`
	Tables         []TableStats                `json:"tables_at_end"`
	Audit          AuditReport                 `json:"audit"`
	Reconcile      *ReconcileReport            `json:"reconciliation,omitempty"`
	Node           MockStats                   `json:"mock_node"`
	OPSLog         map[string]int              `json:"ops_log_messages"`
	FactClock      map[string]uint64           `json:"fact_clock,omitempty"`
	ClockOffsetMS  float64                     `json:"db_minus_host_clock_ms"`
	Series         map[string][]Sample         `json:"series"`
	Errors         []string                    `json:"errors,omitempty"`
	Aborted        string                      `json:"aborted,omitempty"`
	Q6             *Q6Report                   `json:"q6,omitempty"`

	// NodeConnectionsInWindow is the TCP connections OPS opened to the mock
	// node per listener during the steady window: near zero with pooled
	// keep-alive node clients, ~one per call when they churn.
	NodeConnectionsInWindow map[string]int64 `json:"node_connections_opened_in_window"`
}

// AuditReport is the async audit pipeline under the real event mix. Every
// answered RPC request (success or refusal) appends one record.
type AuditReport struct {
	SealedInWindow     int64   `json:"sealed_in_window"`
	SealRatePerSecond  float64 `json:"seal_rate_per_second"`
	AppendRatePerSec   float64 `json:"append_rate_per_second"`
	BacklogAtWindowEnd int64   `json:"buffer_length_at_window_end"`
	BacklogTrend       float64 `json:"buffer_growth_per_second"`
	OldestAgeAtEndSec  float64 `json:"oldest_unsealed_age_at_window_end_s"`
	DrainSeconds       float64 `json:"drain_seconds_observed"`
	// RecordsPerRequest is sealed records per answered request (k).
	RecordsPerRequest         float64 `json:"records_per_answered_request"`
	RecordsPerRequestMeasured bool    `json:"records_per_request_measured"`
	Drained                   bool    `json:"drained"`
	ProjectedDrainSec         float64 `json:"projected_drain_seconds"`
	BufferBytesAtEnd          int64   `json:"buffer_bytes_at_window_end"`
}

// ReconcileReport is the V2 post-request lifecycle (finalized outcomes in OPS).
type ReconcileReport struct {
	IntentsInWindow      int64            `json:"intents_in_window"`
	FinalizedInWindow    int64            `json:"ops_finalized_in_window"`
	FinalizedPerSecond   float64          `json:"ops_finalized_per_second"`
	BacklogAtWindowEnd   int64            `json:"unreconciled_finalized_backlog_at_window_end"`
	BacklogTrend         float64          `json:"backlog_trend_per_second"`
	BacklogBound         float64          `json:"backlog_bound_5s_x_admission"`
	LagMS                Millis           `json:"finalized_outcome_lag_ms"`
	StatesAtEnd          map[string]int64 `json:"states_at_end"`
	ProjectedDrainSec    float64          `json:"projected_drain_seconds"`
	CensoredLags         int64            `json:"lag_censored_unreconciled"`
	SamplesOverBound     int              `json:"window_samples_over_backlog_bound"`
	TailDrainedWithin30s bool             `json:"tail_drained_within_30s"`
}

// OpenLoopConnections is the default open-loop pool: the offered rate times a
// 250 ms latency budget, between 64 and 4096. A server slower than that at the
// offered rate makes requests wait in the runner (measured as latency from the
// schedule) instead of opening more connections.
func OpenLoopConnections(rate int) int {
	return min(4096, max(64, (rate+3)/4))
}

func freeGiB(path string) float64 {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return -1
	}
	return float64(st.Bavail) * float64(st.Bsize) / (1 << 30)
}

func dirBytes(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// RunGate2 runs one case end to end and returns its report.
func RunGate2(ctx context.Context, c Gate2Config) (*Gate2Report, error) {
	logf := func(format string, args ...any) {
		if c.Log != nil {
			c.Log(format, args...)
		}
	}
	if free := freeGiB(c.Dir); free >= 0 && free < c.MinFreeGiB {
		return nil, fmt.Errorf("only %.1f GiB free (< %.0f GiB); refusing to run", free, c.MinFreeGiB)
	}
	if c.MockProcs <= 0 {
		c.MockProcs = 3
	}
	if c.Loop == "closed" {
		c.Connections = c.Concurrency
	} else if c.Connections <= 0 {
		c.Connections = OpenLoopConnections(c.Rate)
	}
	report := &Gate2Report{Config: c, Clusters: map[string]ClusterDelta{}, PerTx: map[string]float64{}, Statements: map[string][]Statement{}, Series: map[string][]Sample{}, WaitEvents: map[string]int{}}
	report.Machine = machineInfo(c.Dir)
	node := MockNodeConfig{ChainID: 31337, DeploymentID: "perfgate-" + c.Name, PrivateToken: "perfgate-private-" + randomHex(16), BlockTime: time.Second, FinalityLag: c.FinalityLag, Latency: c.Latency}
	stack, err := StartStack(ctx, StackOptions{Name: c.Name, Binary: c.Binary, Mode: c.Mode, Dir: c.Dir, Node: node, SeparateDB: c.SeparateDB, MockProcs: c.MockProcs, ExtraEnv: c.ExtraEnv, Log: c.Log})
	if err != nil {
		return nil, err
	}
	defer stack.Close()
	report.Env = redactEnv(stack.Env)
	logf("stack up at %s (mode %s)", stack.URL, c.Mode)

	senders, err := NewSenders(c.Name, c.Users, c.PerUser)
	if err != nil {
		return nil, err
	}
	seededAt := time.Now()
	if err := stack.Seed(senders, 8); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	logf("seeded %d users, %d wallets, compliance configured", c.Users, len(senders))
	if c.Mode == "reth" {
		if err := stack.ActivateExecutionPolicy(); err != nil {
			return nil, fmt.Errorf("activate execution policy: %w", err)
		}
		logf("baseline execution policy activated (author/reviewer)")
	}
	// The load runs to WindowEnd + Drain, then the audit drain is observed for
	// up to another Drain.
	if runEnd := time.Now().Add(2*time.Second + c.Warmup + c.Window + 2*c.Drain); runEnd.After(seededAt.Add(29 * time.Minute)) {
		return nil, fmt.Errorf("run would outlive the 30 min access tokens issued at seed time")
	}
	seconds := int((c.Warmup + c.Window) / time.Second)
	total := c.Rate * seconds
	if c.Loop == "closed" {
		total = 12_000 * seconds
	}
	txs, err := SignWorkload(senders, 31337, total, runtime.NumCPU())
	if err != nil {
		return nil, err
	}
	addresses := make([]string, len(senders))
	for i, s := range senders {
		addresses[i] = s.Address
	}
	if err := stack.Node.Index(txs, addresses); err != nil {
		return nil, err
	}
	target := Target{URL: stack.URL + "/rpc/" + stack.Org, Bodies: make([][]byte, len(txs)), Tokens: make([]string, len(txs)), Expected: make([]string, len(txs))}
	for i, tx := range txs {
		target.Bodies[i], target.Tokens[i], target.Expected[i] = tx.Body, stack.Tokens[senders[tx.Sender].User], tx.Hash
	}
	logf("signed and indexed %d transactions", len(txs))
	var q6run *Q6Run
	if c.Q6 != nil {
		q := *c.Q6
		q.ExecDSN, q.MainDSN = stack.Env["EXECUTION_DATABASE_URL"], stack.Env["DATABASE_URL"]
		q.AuditDSN = stack.PG.DSN(stack.mainName+"_audit", "postgres", stack.PG.Password)
		q.NodeURL, q.NodeToken, q.DeploymentID, q.Index, q.NodeStats = stack.Node.PrivateURL, node.PrivateToken, node.DeploymentID, stack.Node.Index, stack.Node.Stats
		q.ExecAdmin, q.ExecContainer = stack.ExecAdmin, &stack.ExecPG.Container
		q.Warmup, q.Window, q.FinalityLag = c.Warmup, c.Window, c.FinalityLag
		q.Layout = "same_cluster_with_server_load"
		if stack.ExecPG != stack.PG {
			q.Layout = "separate_instance_with_server_load"
		}
		if q6run, err = PrepareQ6(ctx, q); err != nil {
			return nil, fmt.Errorf("q6 prepare: %w", err)
		}
		defer q6run.Close()
		logf("q6 prototype prepared (variant %s, %s)", q.Variant, q.Layout)
	}
	if c.Mode == "reth" {
		version, err := stack.WaitFactsCurrent(ctx, 60*time.Second)
		if err != nil {
			return nil, fmt.Errorf("node never applied the current fact version: %w", err)
		}
		report.FactClock = map[string]uint64{"before_warmup": version}
	}
	var dbNow time.Time
	hostBefore := time.Now()
	if stack.MainDB.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow) == nil {
		hostAfter := time.Now()
		report.ClockOffsetMS = float64(dbNow.Sub(hostBefore.Add(hostAfter.Sub(hostBefore)/2)).Microseconds()) / 1e3
	}

	start := time.Now().Add(2 * time.Second)
	phases := Phases{Start: start, WindowStart: start.Add(c.Warmup), WindowEnd: start.Add(c.Warmup + c.Window)}
	runCtx, abort := context.WithCancel(ctx)
	defer abort()
	sampleCtx, stopSampling := context.WithCancel(ctx)
	var samplerWG sync.WaitGroup
	var abortReason string
	var seriesMu sync.Mutex
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		sampleSeries(sampleCtx, stack, report, &seriesMu, phases, c, func(reason string) { abortReason = reason; abort() })
	}()

	type snap struct {
		main, exec      ClusterSnapshot
		ops, mock, self float64
		metrics         string
		node            MockStats
		err, cpuErr     error
		nodeErr         error
	}
	takeSnap := func() snap {
		var s snap
		s.main, s.err = SnapshotCluster(ctx, stack.Admin, &stack.PG.Container)
		if s.err == nil && stack.ExecPG != stack.PG {
			s.exec, s.err = SnapshotCluster(ctx, stack.ExecAdmin, &stack.ExecPG.Container)
		}
		var opsErr, mockErr error
		s.ops, opsErr = ProcessCPUSeconds(stack.OPS.Process.Pid)
		s.mock, mockErr = ProcessCPUSeconds(stack.Node.PID)
		s.cpuErr = errors.Join(opsErr, mockErr)
		s.self = SelfCPUSeconds()
		s.metrics, _ = stack.Metrics()
		s.node, s.nodeErr = stack.Node.Stats()
		return s
	}
	var before, after snap
	var snapWG sync.WaitGroup
	snapWG.Add(1)
	go func() {
		defer snapWG.Done()
		time.Sleep(time.Until(phases.WindowStart))
		_ = ResetStatements(ctx, stack.Admin)
		if stack.ExecPG != stack.PG {
			_ = ResetStatements(ctx, stack.ExecAdmin)
		}
		before = takeSnap()
		time.Sleep(time.Until(phases.WindowEnd))
		after = takeSnap()
		report.Statements["main_instance"], _ = TopStatements(ctx, stack.Admin, 20)
		report.WriteStmts, _ = WriteStatements(ctx, stack.Admin)
		if stack.ExecPG != stack.PG {
			report.Statements["tracking_instance"], _ = TopStatements(ctx, stack.ExecAdmin, 10)
		}
		if c.Mode == "reth" {
			var version uint64
			if stack.MainDB.QueryRowContext(ctx, `SELECT version FROM node_policy_clock`).Scan(&version) == nil {
				report.FactClock["window_end"] = version
			}
		}
	}()

	var q6Done chan struct{}
	var q6Err error
	if q6run != nil {
		q6Done = make(chan struct{})
		go func() {
			defer close(q6Done)
			report.Q6, q6Err = q6run.Run(runCtx, phases, stack.Node.Stamps)
		}()
	}
	// Requests are bounded by the run deadline, not by a per-request client
	// timeout (R12.1): whatever is still in flight at the end of the drain
	// bound is unfinished and counts as a rejection, as before.
	loadCtx, stopLoad := context.WithDeadline(runCtx, phases.WindowEnd.Add(c.Drain))
	defer stopLoad()
	client := NewLoadClient(c.Connections)
	var records []RequestRecord
	if c.Loop == "closed" {
		time.Sleep(time.Until(start))
		records = ClosedLoop(loadCtx, client, target, c.Concurrency, phases.WindowEnd)
		if len(records) == len(target.Bodies) {
			report.Errors = append(report.Errors, "closed loop ran out of pre-signed transactions before the window ended; the rate is understated")
		}
	} else {
		records = OpenLoop(loadCtx, client, target, c.Rate, total, start, c.Connections)
	}
	stopLoad()
	client.CloseIdleConnections()
	snapWG.Wait()
	if q6Done != nil {
		<-q6Done
		if q6Err != nil {
			report.Errors = append(report.Errors, "q6: "+q6Err.Error())
		}
	}
	logf("load finished; observing drain up to %s", c.Drain)
	report.Audit.Drained, report.Audit.DrainSeconds = waitAuditDrain(ctx, stack, c.Drain)
	stopSampling()
	samplerWG.Wait()
	report.Aborted = abortReason

	report.Window = Account(records, phases)
	if !report.Window.Valid {
		report.Errors = append(report.Errors, "invalid result: "+report.Window.InvalidReason)
	}
	if w := report.Window; c.Loop == "open" && abortReason == "" && (w.NotSent > 0 || w.PeakInFlight >= c.Connections) {
		report.Errors = append(report.Errors, fmt.Sprintf("runner pool saturated (peak %d of %d in flight, %d not sent): OPS saw at most %d concurrent requests; rerun with a larger OPS_GATE2_CONNECTIONS before reading this as OPS capacity", w.PeakInFlight, c.Connections, w.NotSent, c.Connections))
	}
	if before.nodeErr == nil && after.nodeErr == nil {
		// With Q6 on, "private" also counts the prototype's own node client.
		report.NodeConnectionsInWindow = map[string]int64{}
		for listener, n := range after.node.ConnectionsOpened {
			report.NodeConnectionsInWindow[listener] = n - before.node.ConnectionsOpened[listener]
		}
	} else {
		report.Errors = append(report.Errors, fmt.Sprintf("mock stats at a window edge: %v %v", before.nodeErr, after.nodeErr))
	}
	if before.err != nil || after.err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("snapshot: %v %v", before.err, after.err))
	} else {
		report.Clusters["main_instance"] = Delta(before.main, after.main)
		if stack.ExecPG != stack.PG {
			report.Clusters["tracking_instance"] = Delta(before.exec, after.exec)
		}
	}
	if before.cpuErr != nil || after.cpuErr != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("process cpu: %v %v", before.cpuErr, after.cpuErr))
	}
	if before.metrics == "" || after.metrics == "" {
		report.Errors = append(report.Errors, "metrics scrape failed at a window edge")
	}
	report.OPSCPUSeconds = after.ops - before.ops
	report.MockCPUSeconds = after.mock - before.mock
	report.RunnerCPU = after.self - before.self
	report.ServerStages = histogramDeltas(before.metrics, after.metrics)
	report.ServerCounters = counterDeltas(before.metrics, after.metrics, "privacyproxy_db_pool_wait", "privacyproxy_concurrency_rejections", "privacyproxy_rate_limit_hits", "privacyproxy_circuit_breaker", "privacyproxy_rpc_requests_total", "privacyproxy_compliance_decisions_total")
	_ = os.WriteFile(filepath.Join(c.Dir, "ops-metrics-window-start.txt"), []byte(before.metrics), 0o600)
	_ = os.WriteFile(filepath.Join(c.Dir, "ops-metrics-window-end.txt"), []byte(after.metrics), 0o600)
	if done := float64(report.Window.CompletedInWindow); done > 0 && before.err == nil && after.err == nil {
		d := report.Clusters["main_instance"]
		report.PerTx["main_instance_wal_bytes_per_tx"] = float64(d.WALBytes) / done
		report.PerTx["main_instance_write_xacts_per_tx"] = float64(d.WriteTransactions) / done
		report.PerTx["main_instance_wal_syncs_per_tx"] = float64(d.WAL.Syncs) / done
		report.PerTx["main_instance_db_cpu_ms_per_1k_tx"] = d.CPUSeconds * 1e6 / done
		report.PerTx["ops_cpu_ms_per_1k_tx"] = report.OPSCPUSeconds * 1e6 / done
		for name, delta := range d.Databases {
			if strings.HasPrefix(name, stack.mainName) {
				report.PerTx[name+"_xact_commits_per_tx"] = float64(delta.Commits) / done
			}
		}
	}
	for _, database := range []struct {
		name string
		db   *sql.DB
	}{{stack.mainName, stack.MainDB}, {stack.mainName + "_audit", stack.AuditDB}} {
		tables, _ := LargestTables(ctx, database.db, database.name, 6)
		report.Tables = append(report.Tables, tables...)
	}
	stamps, err := stack.Node.Stamps()
	if err != nil {
		report.Errors = append(report.Errors, "stamps: "+err.Error())
	}
	report.Stages = stageTimings(records, target.Expected, stamps, phases)
	summarizeAudit(report, records, phases)
	if c.Mode == "reth" {
		report.Reconcile = reconcileReport(ctx, stack, report, stamps, phases, time.Duration(report.ClockOffsetMS*float64(time.Millisecond)))
	}
	report.Node, _ = stack.Node.Stats()
	if report.Node.StalledTxs > 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("%d transactions from %d senders wait behind nonce gaps left by rejections; finalization and backlog figures exclude them", report.Node.StalledTxs, report.Node.StalledSenders))
	}
	if mockCores := report.MockCPUSeconds / c.Window.Seconds(); mockCores > 0.8*float64(c.MockProcs) {
		report.Errors = append(report.Errors, fmt.Sprintf("mock node used %.2f cores of its %d: node latency may be inflated", mockCores, c.MockProcs))
	}
	report.OPSLog = classifyLog(filepath.Join(c.Dir, "ops.log"))
	report.MachineEnd = machineInfo(c.Dir)
	return report, nil
}

func redactEnv(env map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range env {
		switch {
		case strings.Contains(k, "SECRET") || strings.Contains(k, "TOKEN") || strings.Contains(k, "PASSWORD"):
			out[k] = "<redacted>"
		case strings.Contains(v, "://") && strings.Contains(v, "@"):
			scheme, rest, _ := strings.Cut(v, "://")
			_, host, _ := strings.Cut(rest, "@")
			out[k] = scheme + "://<redacted>@" + host
		default:
			out[k] = v
		}
	}
	return out
}

// machineInfo records the contention context of a run (plan §9.2, V1-12).
func machineInfo(dir string) map[string]any {
	info := map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "cpus": runtime.NumCPU(), "go": runtime.Version(), "free_gib": freeGiB(dir), "at": time.Now().UTC().Format(time.RFC3339)}
	for key, cmd := range map[string][]string{
		"loadavg": {"sysctl", "-n", "vm.loadavg"}, "cpu": {"sysctl", "-n", "machdep.cpu.brand_string"}, "model": {"sysctl", "-n", "hw.model"},
		"portrange": {"sysctl", "-n", "net.inet.ip.portrange.first", "net.inet.ip.portrange.last"}, "tcp_msl": {"sysctl", "-n", "net.inet.tcp.msl"},
		"somaxconn": {"sysctl", "-n", "kern.ipc.somaxconn"}, "thermal": {"pmset", "-g", "therm"}, "power": {"pmset", "-g", "batt"},
		"docker_containers": {"sh", "-c", "docker ps -q | wc -l"},
		"orbstack_cpu":      {"sh", "-c", "ps -A -o %cpu=,comm= | grep -i -E 'orb|vz' | awk '{s+=$1} END {print s}'"},
	} {
		if out, err := runQuiet(cmd[0], cmd[1:]...); err == nil {
			info[key] = out
		}
	}
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) == nil {
		info["nofile"] = limit.Cur
	}
	return info
}

func timeWait() int {
	// Absolute path: the test's PATH need not contain /usr/sbin, and a missing
	// netstat made this sampler report 0 in every P0 run.
	out, err := runQuiet("sh", "-c", "/usr/sbin/netstat -an -p tcp | grep -c TIME_WAIT || true")
	if err != nil {
		return -1
	}
	n, _ := strconv.Atoi(out)
	return n
}

// sampleSeries records one point per second without scanning tables under
// test: sealed audit sequence, buffer size, mock finality counters, TIME_WAIT
// sockets, free disk and Postgres wait events (window only).
func sampleSeries(ctx context.Context, stack *Stack, report *Gate2Report, mu *sync.Mutex, p Phases, c Gate2Config, abort func(string)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	add := func(name string, at time.Time, v float64) {
		mu.Lock()
		report.Series[name] = append(report.Series[name], Sample{At: at, Value: v})
		mu.Unlock()
	}
	bufferDir := stack.Env["AUDIT_BUFFER_DIR"]
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-ticker.C:
			var sealed sql.NullInt64
			if err := stack.AuditDB.QueryRowContext(ctx, sealedSeqQuery).Scan(&sealed); err == nil {
				add("audit_sealed_seq", at, float64(sealed.Int64))
			}
			add("audit_buffer_bytes", at, float64(dirBytes(bufferDir)))
			if stats, err := stack.Node.Stats(); err == nil {
				add("node_included", at, float64(stats.Included))
				add("node_finalized", at, float64(stats.FinalizedTxs))
				add("node_final_status_answered", at, float64(stats.FinalAnswered))
				add("unreconciled_finalized_backlog", at, float64(stats.FinalizedTxs-stats.FinalAnswered))
			}
			add("time_wait_sockets", at, float64(timeWait()))
			free := freeGiB(c.Dir)
			add("free_gib", at, free)
			if free >= 0 && free < c.MinFreeGiB {
				abort(fmt.Sprintf("free disk %.1f GiB below %.0f GiB at %s", free, c.MinFreeGiB, at.Format(time.RFC3339)))
			}
			if !at.Before(p.WindowStart) && at.Before(p.WindowEnd) {
				if events, err := WaitEvents(ctx, stack.Admin); err == nil {
					mu.Lock()
					for k, v := range events {
						report.WaitEvents[k] += v
					}
					mu.Unlock()
				}
			}
		}
	}
}

// sealedSeqQuery reads how far the audit sealer got: the highest sealed
// buffer sequence, as an offset within its allocation range (RD-1410: each
// OPS start numbers its entries in a range of 2^40 of its own; a tree from
// before ranges numbers from 1, which the mask leaves unchanged).
const sealedSeqQuery = `SELECT MAX(buffer_seq) & ((1::bigint << 40) - 1) FROM access_logs`

func waitAuditDrain(ctx context.Context, stack *Stack, limit time.Duration) (bool, float64) {
	start := time.Now()
	var previous int64 = -1
	stable := 0
	for time.Since(start) < limit {
		var sealed sql.NullInt64
		if err := stack.AuditDB.QueryRowContext(ctx, sealedSeqQuery).Scan(&sealed); err != nil {
			return false, time.Since(start).Seconds()
		}
		if sealed.Int64 == previous {
			stable++
			if stable >= 3 { // three sealer ticks without progress: buffer empty
				return true, time.Since(start).Seconds() - 3
			}
		} else {
			stable = 0
		}
		previous = sealed.Int64
		time.Sleep(time.Second)
	}
	return false, time.Since(start).Seconds()
}

func seriesBetween(series []Sample, from, to time.Time) []Sample {
	var out []Sample
	for _, s := range series {
		if !s.At.Before(from) && s.At.Before(to) {
			out = append(out, s)
		}
	}
	return out
}

func valueAt(series []Sample, at time.Time) (float64, bool) {
	sample, ok := sampleAt(series, at)
	return sample.Value, ok
}

// sampleAt is the last sample taken at or before at.
func sampleAt(series []Sample, at time.Time) (Sample, bool) {
	var best *Sample
	for i := range series {
		if !series[i].At.After(at) {
			best = &series[i]
		}
	}
	if best == nil {
		return Sample{}, false
	}
	return *best, true
}

// stageTimings splits successful in-window requests at the mock's arrival
// and reply stamps: before transport (OPS work up to the node call), the
// node call, and after transport (OPS work after the node replied).
func stageTimings(records []RequestRecord, expected []string, stamps map[string]Stamp, p Phases) map[string]Millis {
	var pre, nodeCall, post []time.Duration
	for i, r := range records {
		if !r.OK || p.of(r.Scheduled) != "window" {
			continue
		}
		s, ok := stamps[expected[i]]
		if !ok || s.Arrived == 0 || s.Replied == 0 {
			continue
		}
		arrived, replied := time.Unix(0, s.Arrived), time.Unix(0, s.Replied)
		pre = append(pre, arrived.Sub(r.Sent))
		nodeCall = append(nodeCall, replied.Sub(arrived))
		post = append(post, r.Done.Sub(replied))
	}
	return map[string]Millis{"ops_before_transport": Percentiles(pre), "node_call": Percentiles(nodeCall), "ops_after_transport": Percentiles(post)}
}

// summarizeAudit derives buffer length and oldest unsealed age from the sealed
// sequence and the runner's own answer times (access_logs.created_at is the
// seal time, so it cannot give the age). Records per answered request (k) is
// measured from the drained total when the buffer drained, else assumed 1.
func summarizeAudit(report *Gate2Report, records []RequestRecord, p Phases) {
	sealed := report.Series["audit_sealed_seq"]
	first, ok0 := sampleAt(sealed, p.Start)
	start, ok1 := sampleAt(sealed, p.WindowStart)
	end, ok2 := sampleAt(sealed, p.WindowEnd)
	if !ok0 || !ok1 || !ok2 {
		return
	}
	var answered []time.Time
	for _, r := range records {
		if !r.Done.IsZero() {
			answered = append(answered, r.Done)
		}
	}
	sort.Slice(answered, func(i, j int) bool { return answered[i].Before(answered[j]) })
	answeredBy := func(at time.Time) int {
		return sort.Search(len(answered), func(i int) bool { return answered[i].After(at) })
	}
	a := &report.Audit
	a.RecordsPerRequest, a.RecordsPerRequestMeasured = 1, false
	if final := sealed[len(sealed)-1].Value; report.Audit.Drained && len(answered) > 0 {
		a.RecordsPerRequest, a.RecordsPerRequestMeasured = (final-first.Value)/float64(len(answered)), true
	}
	k := a.RecordsPerRequest
	seconds := end.At.Sub(start.At).Seconds()
	if seconds <= 0 {
		return
	}
	a.SealedInWindow = int64(end.Value - start.Value)
	a.SealRatePerSecond = (end.Value - start.Value) / seconds
	a.AppendRatePerSec = k * float64(answeredBy(end.At)-answeredBy(start.At)) / seconds
	a.BacklogAtWindowEnd = int64(k*float64(answeredBy(end.At)) - (end.Value - first.Value))
	a.BacklogTrend = a.AppendRatePerSec - a.SealRatePerSecond
	// The oldest unsealed record belongs to answered request number sealed/k.
	if next := int((end.Value - first.Value) / k); next >= 0 && next < len(answered) && answered[next].Before(end.At) {
		a.OldestAgeAtEndSec = end.At.Sub(answered[next]).Seconds()
	}
	if a.SealRatePerSecond > 0 {
		a.ProjectedDrainSec = float64(a.BacklogAtWindowEnd) / a.SealRatePerSecond
	}
	if b, ok := valueAt(report.Series["audit_buffer_bytes"], p.WindowEnd); ok {
		a.BufferBytesAtEnd = int64(b)
	}
}

func reconcileReport(ctx context.Context, stack *Stack, report *Gate2Report, stamps map[string]Stamp, p Phases, offset time.Duration) *ReconcileReport {
	r := &ReconcileReport{StatesAtEnd: map[string]int64{}}
	windowSeconds := p.WindowEnd.Sub(p.WindowStart).Seconds()
	// Database timestamps are on the VM clock: db = host + offset. The
	// execution path tracks transactions in the execution-tracking database
	// (RD-1410): bindings until final, then insert-once status rows.
	// Intents = submissions answered inside the window (each answered
	// submission's binding was committed before it was sent).
	r.IntentsInWindow = int64(report.Window.CompletedInWindow)
	_ = stack.ExecDB.QueryRowContext(ctx, `SELECT count(*) FROM node_tx_status WHERE final_at >= $1 AND final_at < $2`, p.WindowStart.Add(offset), p.WindowEnd.Add(offset)).Scan(&r.FinalizedInWindow)
	r.FinalizedPerSecond = float64(r.FinalizedInWindow) / windowSeconds
	series := report.Series["unreconciled_finalized_backlog"]
	r.BacklogTrend = Trend(seriesBetween(series, p.WindowStart, p.WindowEnd))
	if v, ok := valueAt(series, p.WindowEnd); ok {
		r.BacklogAtWindowEnd = int64(v)
	}
	r.BacklogBound = 5 * float64(r.IntentsInWindow) / windowSeconds
	for _, s := range seriesBetween(series, p.WindowStart, p.WindowEnd) {
		if s.Value > r.BacklogBound {
			r.SamplesOverBound++
		}
	}
	r.TailDrainedWithin30s = false
	for _, s := range seriesBetween(series, p.WindowEnd, p.WindowEnd.Add(30*time.Second)) {
		if s.Value <= 0 {
			r.TailDrainedWithin30s = true
			break
		}
	}
	if r.FinalizedPerSecond > 0 {
		r.ProjectedDrainSec = float64(r.BacklogAtWindowEnd) / r.FinalizedPerSecond
	}
	if rows, err := stack.ExecDB.QueryContext(ctx, `SELECT CASE state WHEN 1 THEN 'pending' WHEN 2 THEN 'provisional' WHEN 3 THEN 'renewal_stopped' ELSE 'tombstone' END, count(*) FROM node_tx_binding GROUP BY 1
 UNION ALL SELECT CASE state WHEN 10 THEN 'included' WHEN 11 THEN 'reverted' ELSE 'dropped' END, count(*) FROM node_tx_status GROUP BY 1`); err == nil {
		for rows.Next() {
			var state string
			var n int64
			if rows.Scan(&state, &n) == nil {
				r.StatesAtEnd[state] = n
			}
		}
		rows.Close()
	}
	reconciled := map[string]time.Time{}
	queried := time.Now()
	if rows, err := stack.ExecDB.QueryContext(ctx, `SELECT '0x' || encode(tx_hash, 'hex'), final_at FROM node_tx_status`); err == nil {
		for rows.Next() {
			var hash string
			var at time.Time
			if rows.Scan(&hash, &at) == nil {
				reconciled[hash] = at.Add(-offset)
			}
		}
		rows.Close()
	}
	// Lag over every transaction the node finalized inside the window. Those
	// not yet final in OPS are censored at the query time, so a falling-behind
	// reconciler cannot improve its own percentile.
	var lags []time.Duration
	for hash, s := range stamps {
		if s.Finalized == 0 {
			continue
		}
		finalizedAt := time.Unix(0, s.Finalized)
		if finalizedAt.Before(p.WindowStart) || !finalizedAt.Before(p.WindowEnd) {
			continue
		}
		if at, ok := reconciled[hash]; ok {
			lags = append(lags, at.Sub(finalizedAt))
		} else {
			r.CensoredLags++
			lags = append(lags, queried.Sub(finalizedAt))
		}
	}
	r.LagMS = Percentiles(lags)
	return r
}

var logMessage = regexp.MustCompile(`msg="([^"]+)"`)
var logError = regexp.MustCompile(`error="?([^"]{0,80})`)

// classifyLog counts OPS log lines by message and error text.
func classifyLog(path string) map[string]int {
	out := map[string]int{}
	file, err := os.Open(path)
	if err != nil {
		return out
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "level=WARN") && !strings.Contains(line, "level=ERROR") {
			continue
		}
		key := "?"
		if m := logMessage.FindStringSubmatch(line); m != nil {
			key = m[1]
		}
		if m := logError.FindStringSubmatch(line); m != nil {
			key += " | " + m[1]
		}
		if len(out) < 200 || out[key] > 0 {
			out[key]++
		}
	}
	return out
}

// WriteReport stores the report as indented JSON.
func WriteReport(path string, report *Gate2Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
