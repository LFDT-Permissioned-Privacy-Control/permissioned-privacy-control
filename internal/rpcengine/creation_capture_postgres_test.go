package rpcengine_test

import (
	"encoding/json"
	"testing"
	"time"

	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/walletops"
)

func TestCreationCaptureActualBothModesHTTPPostgres(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"pending-first-and-duplicate", "known-mined-no-new-coverage", "capture-unavailable-no-effects", "ordinary-no-creation-no-readiness-dependency", "empty-ingress-denies-creation", "empty-ingress-denies-ordinary"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := creationIntentRuntimeFixture()
				f.creationObserved = true
				f.rawMode = mode
				n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
				n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
				if scenario == "known-mined-no-new-coverage" {
					n.captureMined = true
				}
				if scenario == "capture-unavailable-no-effects" {
					n.captureUnavailable = true
				}
				if scenario == "ordinary-no-creation-no-readiness-dependency" || scenario == "empty-ingress-denies-ordinary" {
					n.mutate = nil
				}
				if scenario == "empty-ingress-denies-creation" || scenario == "empty-ingress-denies-ordinary" {
					f.readOnly = true
					f.groups[0].IsOrgAdmin = true
					f.groups[0].Claims = []string{}
				}
				e, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
				if scenario == "ordinary-no-creation-no-readiness-dependency" {
					key := financial.Metadata().NetworkKey
					if _, err := d.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET capture_ready=false,capture_heartbeat_until=NULL WHERE network_key=$1`, key[:]); err != nil {
						t.Fatal(err)
					}
				}
				tx := rawTransaction(t, []byte{1, 2})
				out := lifecycleSubmission(t, e, tok, n, tx, nil)
				allowed := scenario == "pending-first-and-duplicate" || scenario == "known-mined-no-new-coverage" || scenario == "ordinary-no-creation-no-readiness-dependency"
				if (out.Error == nil) != allowed {
					t.Fatal("actual covered route outcome", out)
				}
				key := financial.Metadata().NetworkKey
				plans, wallets, factories, work := creationCounts(t, d, key, tx.Hash())
				var covered int
				if err := d.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND tx_hash=$2`, key[:], tx.Hash().Bytes()).Scan(&covered); err != nil {
					t.Fatal(err)
				}
				if scenario == "pending-first-and-duplicate" {
					if plans != 1 || wallets != 0 || factories != 1 || work != 1 || covered != 1 {
						t.Fatal("missing atomic original coverage", plans, wallets, factories, work, covered)
					}
					if retry := lifecycleSubmission(t, e, tok, n, tx, nil); retry.Error != nil {
						t.Fatal("pending duplicate", retry)
					}
					var g, count int64
					if d.owner.QueryRow(t.Context(), `SELECT w.generation,c.capture_coverage_count FROM ops_admission_v2.creation_work w JOIN ops_admission_v2.creation_capacity c USING(network_key)WHERE w.network_key=$1 AND w.tx_hash=$2`, key[:], tx.Hash().Bytes()).Scan(&g, &count) != nil || g != 1 || count != 1 {
						t.Fatal("timing-only duplicate spent slots", g, count)
					}
				} else if plans+wallets+factories+work+covered != 0 {
					t.Fatal("nonqualifying path minted intent/coverage", plans, wallets, factories, work, covered)
				}
				if !allowed {
					if counts := rawCounts(t, d, key, tx.Hash()); counts != (admissionCounts{}) {
						t.Fatal("denied before financial effects", counts)
					}
					methods, _ := n.counts()
					for _, m := range methods {
						if m == "eth_sendRawTransaction" {
							t.Fatal("denied raw broadcast")
						}
					}
					if f.readOnly {
						read, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "data": "0x0102"}, nil)
						if read.Error != nil || read.Result == nil || *read.Result != "0xfeed" {
							t.Fatal("empty ingress lost authorized read/simulation", read)
						}
					}
				}
			})
		}
	}
	if _, err := admissionsql.InstalledSchema(t.Context(), d.ownerDSN); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"factory-first-wallet-later-pending", "relay-first-wallet-later-pending", "fixed-origin-B-readiness-unavailable"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := creationIntentRuntimeFixture()
				f.creationObserved = true
				f.rawMode = mode
				if scenario != "factory-first-wallet-later-pending" {
					f.creationAttribution.Factories = []policybundle.FactoryAttribution{}
				}
				f.linkSigner = scenario == "fixed-origin-B-readiness-unavailable"
				var wallets *walletops.Service
				n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
				n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
				e, tok, financial, snapshot := mountedRawEngine(t, f, n, d, false, creationMountOptions{walletService: func(s *walletops.Service) { wallets = s }})
				tx := rawTransaction(t, []byte{1, 2})
				if out := lifecycleSubmission(t, e, tok, n, tx, nil); out.Error != nil {
					t.Fatal("first submission", out)
				}
				other := tok
				if scenario == "fixed-origin-B-readiness-unavailable" {
					other = tokenSubject(t, snapshot, f.roles, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
				}
				operationalLink(t, wallets, other, tx.Signer())
				key := financial.Metadata().NetworkKey
				if scenario == "fixed-origin-B-readiness-unavailable" {
					if _, err := d.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET capture_ready=false,capture_heartbeat_until=NULL WHERE network_key=$1`, key[:]); err != nil {
						t.Fatal(err)
					}
				}
				if out := lifecycleSubmission(t, e, other, n, tx, nil); out.Error != nil {
					t.Fatal("late current wallet / impossible-B relay", out)
				}
				plans, walletsCount, factories, work := creationCounts(t, d, key, tx.Hash())
				wantFactory := 0
				if scenario == "factory-first-wallet-later-pending" {
					wantFactory = 1
				}
				if plans != 1 || walletsCount != 1 || factories != wantFactory || work != 1 {
					t.Fatal("late wallet/cross-actor refs", plans, walletsCount, factories, work)
				}
				var covered int
				if d.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND tx_hash=$2`, key[:], tx.Hash().Bytes()).Scan(&covered) != nil || covered != 1+wantFactory {
					t.Fatal("missing or borrowed original coverage", covered)
				}
			})
		}
	}
}

func TestCreationCaptureActualBothModesFinancialAtomicity(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		for _, scenario := range []string{"genuine-financial-deny", "financial-allow-covered", "coverage-insert-failure-rolls-back-finance"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				f := creationFinancialFixture(mode)
				f.creationObserved = true
				n := &node{pre: map[string]any{createdAddress: map[string]any{}}}
				n.mutate = func(root map[string]any) { root["calls"] = []any{creationFrame(addressA, createdAddress)} }
				e, tok, financial, snapshot := mountedRawEngine(t, f, n, d, false)
				factory, _ := runtimepolicy.NewFactory(snapshot, func() time.Time { return time.Unix(now, 0) })
				view, err := factory.Build(tok)
				if err != nil {
					t.Fatal(err)
				}
				if scenario != "genuine-financial-deny" {
					response, err := financial.CreateRecord(t.Context(), tok, orgA, admission.CreateRecordRequest{OriginatorActorID: view.ActorID(), OriginatorData: json.RawMessage(`{"name":"origin"}`), BeneficiaryData: json.RawMessage(`{"name":"beneficiary"}`), TransferType: compliance.TransferTypeETH, BeneficiaryAddress: addressA, AmountWei: "3000000000000000000"})
					if err != nil {
						t.Fatal(err)
					}
					materialize(t, response)
				}
				if scenario == "coverage-insert-failure-rolls-back-finance" {
					if _, err := d.owner.Exec(t.Context(), `REVOKE INSERT ON ops_admission_v2.creation_capture_coverage FROM raw_app`); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := d.owner.Exec(t.Context(), `GRANT INSERT ON ops_admission_v2.creation_capture_coverage TO raw_app`); err != nil {
							t.Error(err)
						}
					}()
				}
				tx := signedValue(t, 9)
				out := lifecycleSubmission(t, e, tok, n, tx, []string{view.ActorID()})
				allowed := scenario == "financial-allow-covered"
				if (out.Error == nil) != allowed {
					t.Fatal("financial+capture outcome", out)
				}
				key := financial.Metadata().NetworkKey
				plans, wallets, factories, work := creationCounts(t, d, key, tx.Hash())
				counts := rawCounts(t, d, key, tx.Hash())
				var covered int
				if d.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND tx_hash=$2`, key[:], tx.Hash().Bytes()).Scan(&covered) != nil {
					t.Fatal("coverage count")
				}
				if allowed {
					if plans != 1 || wallets != 1 || factories != 1 || work != 1 || covered != 2 || counts != (admissionCounts{used: 1, allowed: 1, origins: 1, shares: 1}) {
						t.Fatal("financial and coverage not one commit", plans, wallets, factories, work, covered, counts)
					}
				} else {
					want := admissionCounts{}
					if scenario == "genuine-financial-deny" {
						want.denied = 1
					}
					if plans+wallets+factories+work+covered != 0 || counts != want {
						t.Fatal("partial covered financial effects", plans, wallets, factories, work, covered, counts)
					}
				}
				if !allowed {
					methods, _ := n.counts()
					for _, m := range methods {
						if m == "eth_sendRawTransaction" {
							t.Fatal("failed finance/coverage broadcast")
						}
					}
				}
			})
		}
	}
}
