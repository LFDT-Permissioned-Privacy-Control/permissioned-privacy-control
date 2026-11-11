package rpcengine_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
)

// Hooks wrap an ACTUAL committed transaction. They cannot mint a receipt or
// permission and preserve the real covered store's capability/atomic effects.
type nativeCommitGate struct {
	*admissionsql.Store
	after   func(admission.Scope)
	commits atomic.Int32
}

func (s *nativeCommitGate) finish(scope admission.Scope, r admission.CommitReceipt, err error) (admission.CommitReceipt, error) {
	if err == nil && r.Committed && r.Kind == admission.CommitAllow {
		s.commits.Add(1)
		if s.after != nil {
			s.after(scope)
		}
	}
	return r, err
}
func (s *nativeCommitGate) WithRawTransaction(ctx context.Context, scope admission.Scope, f func(admission.RawTx) (admission.CommitKind, error)) (admission.CommitReceipt, error) {
	r, err := s.Store.WithRawTransaction(ctx, scope, f)
	return s.finish(scope, r, err)
}
func (s *nativeCommitGate) WithCoveredRawTransaction(ctx context.Context, scope admission.Scope, b admission.CaptureCommitBinding, f func(admission.RawTx) (admission.CommitKind, error)) (admission.CommitReceipt, error) {
	r, err := s.Store.WithCoveredRawTransaction(ctx, scope, b, f)
	return s.finish(scope, r, err)
}

func TestNativeCurrentActualRawPostCommitFenceBothModes(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"positive", "initial-wrong-genesis", "postcommit-A3-unready", "postcommit-node-reorg", "postcommit-wrong-genesis", "quote-expiry-during-final-probe"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				var clock atomic.Int64
				clock.Store(now)
				wall := func() time.Time { return time.Unix(clock.Load(), 0) }
				f := creationIntentRuntimeFixture()
				f.creationObserved = true
				f.rawMode = mode
				f.clock = &clock
				producer := &faultProducer{batches: make(chan []byte, 16)}
				f.producer = producer
				f.capability("inputs.price-quotes/v1")
				f.capability("operational.travel-rule/v1")
				f.complianceHook = func(source *compliancepolicy.Source) {
					for i := range source.Organizations {
						o := &source.Organizations[i]
						o.RecordMaxSeconds = 30
						o.PriceMaxAgeSeconds = 10
						o.Spec.Settings = compliancepolicy.SourceSettings{Enabled: true, Currency: "usd", ThresholdFiat: 1000, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}
						o.Spec.TokenPrices = []compliancepolicy.SourceTokenPrice{{ID: "dddddddd-dddd-4ddd-8ddd-" + strings.Repeat("0", 11) + string(rune('1'+i)), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{}, CoingeckoID: "ethereum"}}
					}
				}
				n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
				n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
				var gate *nativeCommitGate
				options := creationMountOptions{quoteProvider: currentQuotes{wall}, wrap: func(store *admissionsql.Store) admission.Store { gate = &nativeCommitGate{Store: store}; return gate }}
				engine, token, financial, _ := mountedRawEngine(t, f, n, d, false, options)
				key := financial.Metadata().NetworkKey
				gate.after = func(scope admission.Scope) {
					switch scenario {
					case "postcommit-A3-unready":
						if _, err := d.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET ready=false,quarantine='coverage-gap',capture_ready=false,capture_heartbeat_until=NULL WHERE network_key=$1`, scope.Network[:]); err != nil {
							t.Error(err)
						}
					case "postcommit-node-reorg":
						n.mu.Lock()
						n.anchorHeader = types.CopyHeader(n.anchorHeader)
						n.anchorHeader.Extra = []byte("post-financial-commit-canonical-reorg")
						n.mu.Unlock()
					case "postcommit-wrong-genesis":
						n.mu.Lock()
						n.genesisHeader = types.CopyHeader(n.genesisHeader)
						n.genesisHeader.Extra = []byte("other-deployment-after-commit")
						n.anchorHeader = types.CopyHeader(n.anchorHeader)
						n.anchorHeader.ParentHash = n.genesisHeader.Hash()
						n.mu.Unlock()
					case "quote-expiry-during-final-probe":
						n.mu.Lock()
						n.onChain = func() { clock.Store(now + 11) }
						n.mu.Unlock()
					}
				}
				if scenario == "initial-wrong-genesis" {
					n.mu.Lock()
					n.genesisHeader = types.CopyHeader(n.genesisHeader)
					n.genesisHeader.Extra = []byte("wrong-initial-deployment")
					n.anchorHeader = types.CopyHeader(n.anchorHeader)
					n.anchorHeader.ParentHash = n.genesisHeader.Hash()
					n.mu.Unlock()
				}
				tx := signedValue(t, 90)
				out := lifecycleSubmission(t, engine, token, n, tx, nil)
				methods, _ := n.counts()
				broadcasts, prepares := 0, 0
				for _, method := range methods {
					if method == "eth_sendRawTransaction" {
						broadcasts++
					}
					if method == "debug_traceCall" {
						prepares++
					}
				}
				if scenario == "positive" {
					if out.Error != nil || broadcasts != 1 || gate.commits.Load() != 1 {
						t.Fatal("approved original source failed", out, broadcasts, gate.commits.Load())
					}
					if mode == policybundle.RawSubmissionGuardV1 {
						select {
						case <-producer.batches:
						case <-time.After(time.Second):
							t.Fatal("positive Guard approval not delivered")
						}
					}
					return
				}
				if out.Error == nil || broadcasts != 0 {
					t.Fatal("changed source reached effect", out, broadcasts, scenario)
				}
				if mode == policybundle.RawSubmissionGuardV1 {
					select {
					case <-producer.batches:
						t.Fatal("changed source enqueued Guard approval")
					case <-time.After(50 * time.Millisecond):
					}
				}
				if scenario == "initial-wrong-genesis" {
					if prepares != 0 || gate.commits.Load() != 0 || rawCounts(t, d, key, tx.Hash()) != (admissionCounts{}) {
						t.Fatal("wrong genesis reached Prepare/finance", prepares, gate.commits.Load())
					}
					return
				}
				if gate.commits.Load() != 1 {
					t.Fatal("negative failed before actual SQL commit", out, gate.commits.Load())
				}
				if counts := rawCounts(t, d, key, tx.Hash()); counts.allowed != 1 {
					t.Fatal("durable prepared decision missing", counts)
				}
				if plans, _, factories, work := creationCounts(t, d, key, tx.Hash()); plans != 1 || factories != 1 || work != 1 {
					t.Fatal("prepared creation intent not durable", plans, factories, work)
				}
				// A committed-but-unpublished decision is not replay permission.
				if scenario == "postcommit-A3-unready" {
					before := gate.commits.Load()
					retry := lifecycleSubmission(t, engine, token, n, tx, nil)
					if retry.Error == nil || gate.commits.Load() != before {
						t.Fatal("cached finance bypassed fresh A3 qualification", retry, gate.commits.Load())
					}
				}
			})
		}
	}
}
