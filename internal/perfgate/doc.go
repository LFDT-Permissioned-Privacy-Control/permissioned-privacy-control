// Package perfgate is the common full-server runner for throughput gate 2
// (OPS alone against a mock node, plan RD-1410 §9.5).
//
// It measures a real OPS server binary, not a processor: real HTTP routes and
// middleware, real JWT login through the development identity provider
// (binary built with -tags mockauth), real Redis, real Postgres for the main,
// audit and execution-tracking databases, configured compliance, and every
// background worker the binary starts (audit sealer, retention, publisher,
// reconciler). Only the execution node is mocked. The mock runs in its own
// process and keeps one coherent pool/chain state for the public JSON-RPC
// methods (legacy path) and the private ops_* API (Reth policy mode): real
// transaction hashes, per-sender nonces with gaps held back, receipts after
// a block, finality after a configured lag, fixed added latency.
//
// The package imports nothing from this repository, so the same runner drives
// the server binaries of different revisions. A run never happens in CI: it
// needs OPS_GATE2=1, docker and a built server binary.
//
//	go build -tags mockauth -o /tmp/ops-server ./cmd/server
//	OPS_GATE2=1 OPS_GATE2_SERVER=/tmp/ops-server OPS_GATE2_MODE=legacy \
//	  OPS_GATE2_OUTPUT=/tmp/gate2/case-1 \
//	  go test ./internal/perfgate -run '^TestGate2$' -v -timeout 60m
//
// Settings (environment):
//
//	OPS_GATE2_MODE          legacy | reth (Reth policy mode, private ops_* API)
//	OPS_GATE2_LOOP          open (fixed offered rate) | closed (fixed concurrency)
//	OPS_GATE2_RATE          offered requests per second (default 5250)
//	OPS_GATE2_CONCURRENCY   closed-loop workers (default 32)
//	OPS_GATE2_LATENCY       added mock-node latency (default 1ms)
//	OPS_GATE2_FINALITY_LAG  mock finality lag (default 1s)
//	OPS_GATE2_WARMUP        default finality lag + 30s (never shorter outside smoke runs)
//	OPS_GATE2_WINDOW        steady window (default 60s)
//	OPS_GATE2_DRAIN         bounded drain observation after the window (default 60s)
//	OPS_GATE2_USERS, OPS_GATE2_WALLETS_PER_USER  linked senders (default 100 × 10)
//	OPS_GATE2_SEPARATE_TRACKING_DB=1  tracking database on its own Postgres instance
//	OPS_GATE2_EXTRA_ENV     K=V,... server overrides for labelled sensitivity runs
//
// Achieved throughput counts only successful responses completed inside the
// steady window; warm-up and drain are excluded, and every non-success
// (HTTP error, JSON-RPC error, transport error, unfinished request) is a
// rejection. The report also carries per-stage latency split at the mock's
// arrival/reply stamps, per-database commit and write-transaction rates, WAL
// bytes and syncs, database and process CPU, audit buffer length, seal rate
// and drain, reconciliation backlog and lag (Reth mode), and the host's
// contention context.
//
// The processor-only RD-1112 harness (internal/server proxy_openloop_test.go
// and proxy_throughput_bench_test.go) is a historical diagnostic, not gate 2.
package perfgate
