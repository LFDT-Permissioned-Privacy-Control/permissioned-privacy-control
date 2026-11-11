package rpcengine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/walletops"
)

type creationMountOptions struct {
	limits        *admission.CreationLimits
	wrap          func(*admissionsql.Store) admission.Store
	walletService func(*walletops.Service)
	configure     func(*rpcengine.RawOptions)
	quoteProvider admission.QuoteProvider
}

type creationCommitFault struct {
	admission.CreationIntentStore
	after   func()
	unknown bool
}

func (s *creationCommitFault) WithRawTransaction(ctx context.Context, scope admission.Scope, callback func(admission.RawTx) (admission.CommitKind, error)) (admission.CommitReceipt, error) {
	receipt, err := s.CreationIntentStore.WithRawTransaction(ctx, scope, callback)
	if err == nil && receipt.Committed && receipt.Kind == admission.CommitAllow {
		if s.after != nil {
			s.after()
		}
		if s.unknown {
			return admission.CommitReceipt{}, admission.ErrUnavailable
		}
	}
	return receipt, err
}

func creationCounts(t *testing.T, d rawDatabase, key admission.Digest, hash common.Hash) (plans, wallets, factories, work int) {
	t.Helper()
	if err := d.owner.QueryRow(t.Context(), `SELECT
 (SELECT count(*)FROM ops_admission_v2.creation_plans WHERE network_key=$1 AND tx_hash=$2),
 (SELECT count(*)FROM ops_admission_v2.creation_authority_refs WHERE network_key=$1 AND tx_hash=$2 AND kind='WALLET'),
 (SELECT count(*)FROM ops_admission_v2.creation_authority_refs WHERE network_key=$1 AND tx_hash=$2 AND kind='FACTORY'),
 (SELECT count(*)FROM ops_admission_v2.creation_work WHERE network_key=$1 AND tx_hash=$2)`, key[:], hash[:]).Scan(&plans, &wallets, &factories, &work); err != nil {
		t.Fatal(err)
	}
	return
}

func creationFinancialFixture(mode string) fixture {
	f := creationIntentRuntimeFixture()
	f.rawMode, f.linkSigner = mode, true
	f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "administrator", Name: "Administrator", IsOrgAdmin: true, AllowedMethods: []string{"eth_call", "eth_sendTransaction"}, Claims: []string{}})
	f.roles = append(f.roles, second)
	f.capability("operational.travel-rule/v1")
	f.complianceHook = func(s *compliancepolicy.Source) {
		for j := range s.Organizations {
			spec := &s.Organizations[j].Spec
			spec.Settings = compliancepolicy.SourceSettings{Enabled: true, Currency: "usd", ThresholdFiat: 1, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}
			spec.TokenPrices = []compliancepolicy.SourceTokenPrice{{ID: fmt.Sprintf("dddddddd-dddd-4ddd-8ddd-%012d", j+1), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{"usd": 1}}}
		}
	}
	return f
}

func TestCreationIntentActualPostgresHTTPFactoryCommitAndRetry(t *testing.T) {
	d := rawPostgres(t)
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		t.Run(mode, func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			f.rawMode = mode
			n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
			n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
			e, tok, _, _ := mountedRawEngine(t, f, n, d, false)
			tx := rawTransaction(t, []byte{1, 2})
			for i := 0; i < 2; i++ {
				out := lifecycleSubmission(t, e, tok, n, tx, nil)
				if out.Error != nil {
					t.Fatal("committed factory submission failed", out.Error)
				}
			}
			var plans, refs, work int
			var generation int64
			if err := d.owner.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM ops_admission_v2.creation_plans WHERE tx_hash=$1),(SELECT count(*) FROM ops_admission_v2.creation_authority_refs WHERE tx_hash=$1),(SELECT count(*) FROM ops_admission_v2.creation_work WHERE tx_hash=$1),(SELECT max(generation) FROM ops_admission_v2.creation_work WHERE tx_hash=$1)`, tx.Hash().Bytes()).Scan(&plans, &refs, &work, &generation); err != nil {
				t.Fatal(err)
			}
			// The two modes have independently namespaced operational networks.
			want := 1
			if mode == policybundle.RawSubmissionGuardV1 {
				want = 2
			}
			if plans != want || refs != want || work != want || generation != 1 {
				t.Fatal("retry changed first immutable intent", plans, refs, work, generation)
			}
		})
	}
}

func TestCreationIntentActualHTTPFinanceRollbackAndKnownCommit(t *testing.T) {
	d := rawPostgres(t)
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"cap-rolls-back-everything", "insert-rolls-back-everything", "compliance-deny", "ambiguous-commit", "postcommit-token-expiry", "own-wallet-and-factory"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := creationFinancialFixture(mode)
				var instant atomic.Int64
				instant.Store(now)
				f.clock = &instant
				producer := &faultProducer{batches: make(chan []byte, 16)}
				f.producer = producer
				n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
				n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
				opts := creationMountOptions{}
				if scenario == "cap-rolls-back-everything" {
					limits := admission.DefaultCreationLimits()
					limits.Bytes = 1
					opts.limits = &limits
				}
				if scenario == "ambiguous-commit" || scenario == "postcommit-token-expiry" {
					opts.wrap = func(store *admissionsql.Store) admission.Store {
						fault := &creationCommitFault{CreationIntentStore: store, unknown: scenario == "ambiguous-commit"}
						if scenario == "postcommit-token-expiry" {
							fault.after = func() { instant.Store(now + 300) }
						}
						return fault
					}
				}
				e, tok, financial, snapshot := mountedRawEngine(t, f, n, d, false, opts)
				factory, _ := runtimepolicy.NewFactory(snapshot, func() time.Time { return time.Unix(instant.Load(), 0) })
				view, err := factory.Build(tok)
				if err != nil {
					t.Fatal(err)
				}
				if scenario != "compliance-deny" {
					response, err := financial.CreateRecord(t.Context(), tok, orgA, admission.CreateRecordRequest{OriginatorActorID: view.ActorID(), OriginatorData: json.RawMessage(`{"name":"origin"}`), BeneficiaryData: json.RawMessage(`{"name":"beneficiary"}`), TransferType: compliance.TransferTypeETH, BeneficiaryAddress: addressA, AmountWei: "3000000000000000000"})
					if err != nil {
						t.Fatal("actual financial record", err)
					}
					materialize(t, response)
				}
				if scenario == "insert-rolls-back-everything" {
					if _, err := d.owner.Exec(t.Context(), `REVOKE INSERT ON ops_admission_v2.creation_authority_refs FROM raw_app`); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := d.owner.Exec(t.Context(), `GRANT INSERT ON ops_admission_v2.creation_authority_refs TO raw_app`); err != nil {
							t.Error(err)
						}
					}()
				}
				tx := signedValue(t, 9)
				out := lifecycleSubmission(t, e, tok, n, tx, []string{view.ActorID()})
				key := financial.Metadata().NetworkKey
				p, w, fct, work := creationCounts(t, d, key, tx.Hash())
				counts := rawCounts(t, d, key, tx.Hash())
				committed := scenario == "ambiguous-commit" || scenario == "postcommit-token-expiry" || scenario == "own-wallet-and-factory"
				if committed {
					if p != 1 || w != 1 || fct != 1 || work != 1 || counts != (admissionCounts{used: 1, allowed: 1, origins: 1, shares: 1}) {
						t.Fatal("known truthful durable allow effects", p, w, fct, work, counts)
					}
				} else {
					want := admissionCounts{}
					if scenario == "compliance-deny" {
						want.denied = 1
					}
					if p+w+fct+work != 0 || counts != want {
						t.Fatal("partial financial/origin/share/intent effects", p, w, fct, work, counts)
					}
				}
				published := scenario == "own-wallet-and-factory"
				if (out.Error == nil) != published {
					t.Fatal("publication not gated by known live COMMIT", out)
				}
				methods, _ := n.counts()
				sends := 0
				for _, method := range methods {
					if method == "eth_sendRawTransaction" {
						sends++
					}
				}
				wantSends := 0
				if published {
					wantSends = 1
				}
				if sends != wantSends || (!published && producer.deliveries.Load() != 0) {
					t.Fatal("unexpected send or Guard delivery", sends, producer.deliveries.Load())
				}
			})
		}
	}
}

func TestCreationIntentActualHTTPUnqualifiedAndNoCreateReserveNothing(t *testing.T) {
	d := rawPostgres(t)
	for _, scenario := range []string{"unlinked-relay", "no-create", "wrong-factory-pin"} {
		t.Run(scenario, func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			if scenario == "unlinked-relay" {
				f.creationAttribution.Factories = []policybundle.FactoryAttribution{}
			}
			if scenario == "wrong-factory-pin" {
				f.creationAttribution.Factories[0].CodeHash = "0x" + strings.Repeat("1", 64)
			}
			n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
			if scenario != "no-create" {
				n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
			}
			e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
			tx := rawTransaction(t, []byte{1, 2})
			out := lifecycleSubmission(t, e, tok, n, tx, nil)
			if out.Error != nil {
				t.Fatal("current native policy still permits relay", out)
			}
			p, w, fct, work := creationCounts(t, d, financial.Metadata().NetworkKey, tx.Hash())
			if p+w+fct+work != 0 {
				t.Fatal("unqualified intent consumed durable capacity", p, w, fct, work)
			}
		})
	}
}

func TestCreationIntentActualHTTPRelayFactoryThenWalletAndDifferentActor(t *testing.T) {
	d := rawPostgres(t)
	for _, scenario := range []string{"relay-first", "factory-first", "fixed-origin-different-actor"} {
		t.Run(scenario, func(t *testing.T) {
			f := creationIntentRuntimeFixture()
			if scenario != "factory-first" {
				f.creationAttribution.Factories = []policybundle.FactoryAttribution{}
			}
			f.linkSigner = scenario == "fixed-origin-different-actor"
			var walletService *walletops.Service
			opts := creationMountOptions{walletService: func(s *walletops.Service) { walletService = s }}
			n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
			n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
			e, tok, financial, snapshot := mountedRawEngine(t, f, n, d, false, opts)
			tx := rawTransaction(t, []byte{1, 2})
			if out := lifecycleSubmission(t, e, tok, n, tx, nil); out.Error != nil {
				t.Fatal("first explicit submission", out)
			}
			key := financial.Metadata().NetworkKey
			p, w, fct, work := creationCounts(t, d, key, tx.Hash())
			if scenario == "relay-first" && p+w+fct+work != 0 || scenario == "factory-first" && (p != 1 || w != 0 || fct != 1 || work != 1) || scenario == "fixed-origin-different-actor" && (p != 1 || w != 1 || fct != 0 || work != 1) {
				t.Fatal("incorrect first capture", p, w, fct, work)
			}
			secondToken := tok
			if scenario == "fixed-origin-different-actor" {
				secondToken = tokenSubject(t, snapshot, f.roles, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
			}
			// Real user challenge/signature links the wallet between requests.
			operationalLink(t, walletService, secondToken, tx.Signer())
			if out := lifecycleSubmission(t, e, secondToken, n, tx, nil); out.Error != nil {
				t.Fatal("explicit wallet-associated retry", out)
			}
			p, w, fct, work = creationCounts(t, d, key, tx.Hash())
			wantFactory, wantGeneration := 0, 1
			if scenario == "factory-first" {
				wantFactory, wantGeneration = 1, 2
			}
			if p != 1 || w != 1 || fct != wantFactory || work != 1 {
				t.Fatal("wallet retry duplicated plan or borrowed Origin", p, w, fct, work)
			}
			var generation int
			if err := d.owner.QueryRow(t.Context(), `SELECT generation FROM ops_admission_v2.creation_work WHERE network_key=$1 AND tx_hash=$2`, key[:], tx.Hash().Bytes()).Scan(&generation); err != nil || generation != wantGeneration {
				t.Fatal("work generation did not track new refs only", generation, err)
			}
			if scenario == "fixed-origin-different-actor" {
				factory, _ := runtimepolicy.NewFactory(snapshot, func() time.Time { return time.Unix(now, 0) })
				original, _ := factory.Build(tok)
				other, _ := factory.Build(secondToken)
				var origin, captured string
				if err := d.owner.QueryRow(t.Context(), `SELECT o.actor_id,r.wallet_actor FROM ops_admission_v2.qualified_tx_origins o JOIN ops_admission_v2.creation_authority_refs r USING(network_key,tx_hash)WHERE o.network_key=$1 AND o.tx_hash=$2 AND r.kind='WALLET'`, key[:], tx.Hash().Bytes()).Scan(&origin, &captured); err != nil || origin != original.ActorID() || captured != origin || captured == other.ActorID() {
					t.Fatal("current actor B borrowed A's historical signer association", origin, captured, err)
				}
				if counts := rawCounts(t, d, key, tx.Hash()); counts.origins != 1 || counts.allowed != 1 {
					t.Fatal("B's permitted relay audit was lost", counts)
				}
			}
		})
	}
}
