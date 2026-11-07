package admissionsql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliancehttp"
	"privacy-proxy/internal/compliancepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
)

type quoteProvider struct{ snapshot a.QuoteSnapshot }

func (p quoteProvider) Capture(context.Context) (a.QuoteSnapshot, error) { return p.snapshot, nil }
func dynamicSource() compliancepolicy.Source {
	s := source()
	for i := range s.Organizations {
		s.Organizations[i].Spec.TokenPrices[0].CoingeckoID = "ethereum"
		s.Organizations[i].Spec.TokenPrices[0].PricesByCurrency = map[string]float64{}
	}
	return s
}
func quotes(t *testing.T, at int64) quoteProvider {
	t.Helper()
	s, err := a.NewQuoteSnapshot([]a.Quote{{ID: "ethereum", Currency: "usd", Value: 1, SourceID: "fixture-provider", FetchedAt: time.Unix(at, 0).UTC(), ProviderAsOf: time.Unix(at, 0).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	return quoteProvider{s}
}

func TestPostgresQuotesAdministrationRecoveryAndRetention(t *testing.T) {
	d := setup(t)
	t.Run("actual source views require true admin and remain read only", func(t *testing.T) {
		x := newFixture(t, d, source())
		readonly := f.Token(t, x.snapshot, f.Subject, "Readonly")
		local := f.Token(t, x.snapshot, f.Subject, "Local")
		for _, section := range []string{"config", "tokens", "address-thresholds", "sanctions", "quotes"} {
			status, body := request(t, x, readonly, "GET", base+section, nil)
			if status != 200 || !bytes.Contains(body, []byte(`"sourceDigest":"sha256:`)) {
				t.Fatalf("source %s %d %s", section, status, body)
			}
			status, _ = request(t, x, local, "GET", base+section, nil)
			if status != 403 {
				t.Fatal("local claim bypass", status)
			}
			status, _ = request(t, x, x.token, "GET", base+section, nil)
			if status != 403 {
				t.Fatal("ordinary member admin", status)
			}
		}
		status, _ := request(t, x, readonly, "POST", base+"travel-rule-records", createRequest(f.Actor(f.Subject)))
		if status != 403 {
			t.Fatal("readonly write", status)
		}
		status, _ = request(t, x, x.admin, "PUT", base+"config", `{}`)
		if status != http.StatusMethodNotAllowed {
			t.Fatal("source mutation route", status)
		}
		status, _ = request(t, x, "", "GET", base+"config", nil)
		if status != 401 {
			t.Fatal("missing auth")
		}
		r := x.record(t, f.Actor(f.Subject))
		foreign := f.Token(t, x.snapshot, f.AdminSubject, "Foreign")
		status, _ = request(t, x, foreign, "GET", "/api/v2/orgs/"+f.OtherOrg+"/compliance/travel-rule-records/"+r.ID, nil)
		if status != 404 {
			t.Fatal("cross org record", status)
		}
	})
	t.Run("closed JSON HTTP bounds and no bulk PII", func(t *testing.T) {
		x := newFixture(t, d, source())
		raw, _ := json.Marshal(createRequest(f.Actor(f.Subject)))
		for _, body := range []string{string(raw[:len(raw)-1]) + `,"amountFiat":100}`, string(raw[:len(raw)-1]) + `,"currency":"eur"}`, string(raw[:len(raw)-1]) + `,"expiresAt":"tomorrow"}`, strings.Replace(string(raw), `"amountWei":`, `"AmountWei":`, 1), strings.Replace(string(raw), `"amountWei":"3000000000000000000"`, `"amountWei":null`, 1), string(raw[:len(raw)-1]) + `,"amountWei":"1"}`, strings.Repeat("x", a.MaxRequestBytes+1)} {
			status, _ := request(t, x, x.admin, "POST", base+"travel-rule-records", body)
			if status != 400 {
				t.Fatal("bad create", status)
			}
		}
		status, _ := request(t, x, x.admin, "POST", base+"preview", strings.Repeat("x", a.MaxPreviewBytes+1))
		if status != 400 {
			t.Fatal("preview limit", status)
		}
		status, _ = request(t, x, x.admin, "GET", base+"events?cursor="+strings.Repeat("a", 16<<10), nil)
		if status != 400 {
			t.Fatal("query cap", status)
		}
		status, _ = request(t, x, x.admin, "GET", base+"events?limit=1&limit=2", nil)
		if status != 400 {
			t.Fatal("repeated query", status)
		}
		status, _ = request(t, x, x.admin, "HEAD", base+"events", nil)
		if status != 405 {
			t.Fatal("head operation", status)
		}
		status, _ = request(t, x, x.admin, "GET", base+"events", `{}`)
		if status != 400 {
			t.Fatal("GET body", status)
		}
		if count(t, x, "travel_records") != 0 {
			t.Fatal("invalid input mutation")
		}
		x.record(t, f.Actor(f.Subject))
		x.record(t, f.Actor(f.Subject))
		status, body := request(t, x, x.admin, "GET", base+"travel-rule-records?limit=1", nil)
		if status != 200 || bytes.Contains(body, []byte("originatorData")) {
			t.Fatal("bulk PII", status)
		}
		var page struct {
			NextCursor string `json:"nextCursor"`
		}
		if json.Unmarshal(body, &page) != nil || page.NextCursor == "" {
			t.Fatal("page cursor")
		}
		other := f.Token(t, x.snapshot, f.Subject, "Admin")
		status, _ = request(t, x, other, "GET", base+"travel-rule-records?limit=1&cursor="+page.NextCursor, nil)
		if status != 409 {
			t.Fatal("cursor viewer", status)
		}
		status, body = request(t, x, x.admin, "GET", base+"travel-rule-records?limit=1&cursor="+page.NextCursor, nil)
		if status != 200 || bytes.Contains(body, []byte("originatorData")) {
			t.Fatal("second bounded page", status)
		}
	})
	t.Run("stale quote is unknown and explicit allow still publishes", func(t *testing.T) {
		src := dynamicSource()
		for i := range src.Organizations {
			src.Organizations[i].Spec.Settings.UnknownPricePolicy = "allowed"
		}
		x := newFixtureQuotes(t, d, src, quotes(t, f.Now-61))
		input := x.input(t, 20, big.NewInt(2e18), x.token, f.Org, false)
		check(t, x.one, input, true)
		var value *string
		var q []byte
		if err := d.owner.QueryRow(t.Context(), `SELECT amount_fiat::text,quote_digest FROM ops_admission_v2.compliance_events WHERE network_key=$1`, x.key[:]).Scan(&value, &q); err != nil || value != nil || q != nil {
			t.Fatal("unknown fabricated valuation", err)
		}
		status, _ := request(t, x, x.admin, "POST", base+"travel-rule-records", createRequest(f.Actor(f.Subject)))
		if status != 422 {
			t.Fatal("unknown quote issued record", status)
		}
	})
	t.Run("stale quote monitor path is not recast as current value", func(t *testing.T) {
		src := dynamicSource()
		for i := range src.Organizations {
			src.Organizations[i].Spec.Settings.EnforcementMode = "monitor"
		}
		x := newFixtureQuotes(t, d, src, quotes(t, f.Now-61))
		input := x.input(t, 21, big.NewInt(2e18), x.token, f.Org, false)
		r := check(t, x.one, input, true)
		if !r.Decision().Monitored {
			t.Fatal("lost monitor flag")
		}
	})
	t.Run("used positive quote expiring before commit rolls back", func(t *testing.T) {
		x := newFixtureQuotes(t, d, dynamicSource(), quotes(t, f.Now))
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 22, big.NewInt(2e18), x.token, f.Org, true)
		s := x.service(t, hookStore{Store: d.one, afterAudit: func() { x.clock.Store(f.Now + 61) }}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if !errors.Is(err, a.ErrValuation) || result != nil {
			t.Fatal("expired quote commit", err)
		}
		checkUnused(t, x, r.ID)
		if count(t, x, "compliance_events") != 0 || count(t, x, "qualified_tx_origins") != 0 {
			t.Fatal("stale quote partial commit")
		}
	})
	t.Run("used positive quote expiring after commit blocks publication", func(t *testing.T) {
		x := newFixtureQuotes(t, d, dynamicSource(), quotes(t, f.Now))
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 23, big.NewInt(2e18), x.token, f.Org, false)
		s := x.service(t, hookStore{Store: d.one, afterCommit: func() { x.clock.Store(f.Now + 61) }}, nil)
		result, err := s.CheckAndRecordRaw(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		receipt, ok := result.Receipt()
		if !ok || !errors.Is(receipt.RequirePublishable(), a.ErrValuation) {
			t.Fatal("stale quote first effect")
		}
	})
	t.Run("numeric comparison does not round an imported fractional cent up", func(t *testing.T) {
		src := source()
		for i := range src.Organizations {
			src.Organizations[i].Spec.Settings.ThresholdFiat = 0.1
			src.Organizations[i].Spec.TokenPrices[0].PricesByCurrency["usd"] = 0.1
		}
		x := newFixture(t, d, src)
		record := a.Record{ID: uuid.NewString(), Network: x.key, Organization: f.Org, Actor: f.Actor(f.Subject), OriginatorData: json.RawMessage(`{}`), BeneficiaryData: json.RawMessage(`{}`), TransferType: "eth", Beneficiary: createBeneficiary(), AmountWei: "3000000000000000000", AmountFiat: 0.3, Currency: "usd", CreatedAt: time.Unix(f.Now, 0).UTC(), ExpiresAt: time.Unix(f.Now+60, 0).UTC(), CreatedBy: f.Actor(f.AdminSubject), PolicyDigest: x.one.Metadata().ComplianceDigest}
		if _, err := d.one.CreateRecord(t.Context(), x.key, x.state, record, func(*a.Record) error { return nil }); err != nil {
			t.Fatal(err)
		}
		input := x.input(t, 24, big.NewInt(3e18), x.token, f.Org, false)
		check(t, x.one, input, false)
		checkUnused(t, x, record.ID)
		// The ordinary source-created 3*0.1 value is retained at its actual
		// float64 shortest decimal rather than forced to a cent boundary.
		resp, err := x.one.CreateRecord(t.Context(), x.admin, f.Org, createRequest(f.Actor(f.Subject)))
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		if _, err := resp.WriteTo(&body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body.Bytes(), []byte(`"amountFiat":0.30000000000000004`)) {
			t.Fatal("cent rounding", body.String())
		}
		check(t, x.two, input, true)
	})
	t.Run("reader app retention roles cannot access legacy or rewrite facts", func(t *testing.T) {
		x := newFixture(t, d, source())
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 25, big.NewInt(2e18), x.token, f.Org, true)
		check(t, x.one, input, true)
		reader, err := admissionsql.OpenReader(t.Context(), d.readerDSN)
		if err != nil {
			t.Fatal("reader startup", err)
		}
		defer reader.Close()
		if _, err := reader.GetRecord(t.Context(), x.key, x.state, f.Org, r.ID); err != nil {
			t.Fatal(err)
		}
		retention, err := admissionsql.OpenRetention(t.Context(), d.retentionDSN)
		if err != nil {
			t.Fatal("retention startup", err)
		}
		defer retention.Close()
		conn, err := pgx.Connect(t.Context(), d.appDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(t.Context())
		for _, sql := range []string{`SELECT * FROM public.users`, `UPDATE ops_admission_v2.network_state SET ready=false`, `UPDATE ops_admission_v2.travel_records SET amount_fiat=100`, `DELETE FROM ops_admission_v2.qualified_tx_origins`, `UPDATE ops_admission_v2.travel_records SET used_tx_hash=decode(repeat('aa',32),'hex')`, `DELETE FROM ops_admission_v2.travel_records WHERE used_at IS NOT NULL`} {
			if _, err := conn.Exec(t.Context(), sql); err == nil {
				t.Fatal("unsafe app statement", sql)
			}
		}
		if _, err := d.owner.Exec(t.Context(), `GRANT SELECT(id) ON public.users TO admission_app`); err != nil {
			t.Fatal(err)
		}
		unsafe, err := admissionsql.Open(t.Context(), d.appDSN)
		if unsafe != nil {
			unsafe.Close()
		}
		if err == nil {
			t.Fatal("column-only legacy access accepted")
		}
		if _, err := d.owner.Exec(t.Context(), `REVOKE SELECT(id) ON public.users FROM admission_app`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("restore generation blocks stale replicas and preserves used facts", func(t *testing.T) {
		x := newFixture(t, d, source())
		r := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 26, big.NewInt(2e18), x.token, f.Org, true)
		input.Audience = []string{f.Actor(f.AdminSubject)}
		check(t, x.one, input, true)
		generation := uuid.NewString()
		if err := admissionsql.BeginRecovery(t.Context(), d.ownerDSN, x.binding, generation); err != nil {
			t.Fatal(err)
		}
		if result, err := x.two.CheckAndRecordRaw(t.Context(), input); !errors.Is(err, a.ErrUnavailable) || result != nil {
			t.Fatal("stale replica", err)
		}
		if err := admissionsql.BootstrapEmpty(t.Context(), d.ownerDSN, x.binding, generation); !errors.Is(err, a.ErrConflict) {
			t.Fatal("bootstrap blessed existing restore", err)
		}
		x.state = a.ExpectedState{Generation: generation, Coverage: a.HashParts("test-restored-complete")}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.ownerDSN, x.binding, x.state, false); !errors.Is(err, a.ErrInvalid) {
			t.Fatal("missing attestation", err)
		}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.ownerDSN, x.binding, x.state, true); err != nil {
			t.Fatal("finalize", err)
		}
		x.one = x.service(t, d.one, nil)
		x.clock.Store(f.Now + 61)
		result := check(t, x.one, input, true)
		if result.Decision().RecordID != r.ID || count(t, x, "qualified_tx_origins") != 1 || count(t, x, "tx_shares") != 1 {
			t.Fatal("stable facts invalidated")
		}
	})
	t.Run("retention keeps every used binding and privacy fact", func(t *testing.T) {
		x := newFixture(t, d, source())
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 27, big.NewInt(2e18), x.token, f.Org, true)
		input.Audience = []string{f.Actor(f.AdminSubject)}
		check(t, x.one, input, true)
		x.record(t, f.Actor(f.Subject))
		x.clock.Store(f.Now + 61)
		other := x.input(t, 28, big.NewInt(2e18), x.token, f.Org, false)
		check(t, x.one, other, false)
		r, err := admissionsql.OpenRetention(t.Context(), d.retentionDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		h := admissionsql.Retention{Logs: time.Hour, Records: time.Hour, Interval: time.Hour, Batch: 1000}
		n, err := r.CleanupOnce(t.Context(), x.key, x.state, time.Unix(f.Now+7200, 0).UTC(), h)
		if err != nil || n != 2 {
			t.Fatal("retention count", n, err)
		}
		if count(t, x, "travel_records") != 1 || count(t, x, "compliance_events") != 1 || count(t, x, "qualified_tx_origins") != 1 || count(t, x, "tx_shares") != 1 {
			t.Fatal("used history pruned")
		}
		zero := h
		zero.Logs = 0
		zero.Records = 0
		if n, err := r.CleanupOnce(t.Context(), x.key, x.state, time.Unix(f.Now+10000, 0), zero); err != nil || n != 0 {
			t.Fatal("keep forever")
		}
	})
	t.Run("compact row payload samples are measured without load test", func(t *testing.T) {
		x := newFixture(t, d, source())
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 29, big.NewInt(2e18), x.token, f.Org, true)
		input.Audience = []string{f.Actor(f.AdminSubject)}
		check(t, x.one, input, true)
		for _, table := range []string{"travel_records", "compliance_events", "qualified_tx_origins", "tx_shares"} {
			var size int
			if err := d.owner.QueryRow(t.Context(), `SELECT pg_column_size(t)FROM ops_admission_v2.`+table+` t WHERE network_key=$1 LIMIT 1`, x.key[:]).Scan(&size); err != nil || size <= 0 {
				t.Fatal(err)
			}
			t.Logf("capacity_sample table=%s payload_bytes=%d fixture_one_Actor_recipient=true excludes_indexes_and_page_overhead=true", table, size)
		}
	})
	t.Run("same scope concurrent retry uses one bound record", func(t *testing.T) {
		x := newFixture(t, d, source())
		record := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 30, big.NewInt(2e18), x.token, f.Org, false)
		results := make(chan *a.CommittedResult, 2)
		failures := make(chan error, 2)
		for _, service := range []*a.Service{x.one, x.two} {
			go func(s *a.Service) {
				r, err := s.CheckAndRecordRaw(t.Context(), input)
				if err != nil {
					failures <- err
					return
				}
				results <- r
			}(service)
		}
		for i := 0; i < 2; i++ {
			select {
			case err := <-failures:
				t.Fatal(err)
			case r := <-results:
				if !r.Decision().Allowed || r.Decision().RecordID != record.ID {
					t.Fatal("retry not bound")
				}
			}
		}
		if count(t, x, "travel_records") != 1 || count(t, x, "compliance_events") != 2 {
			t.Fatal("retry amplification")
		}
	})
	t.Run("receipt requires same opaque execution instance", func(t *testing.T) {
		x := newFixture(t, d, source())
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 31, big.NewInt(2e18), x.token, f.Org, true)
		r := check(t, x.one, input, true)
		receipt, _ := r.Receipt()
		other := x.input(t, 31, big.NewInt(2e18), x.token, f.Org, true)
		if receipt.Matches(other) {
			t.Fatal("detached re-created execution borrowed receipt")
		}
		other = input
		other.Audience = []string{f.Actor(f.AdminSubject)}
		if receipt.Matches(other) {
			t.Fatal("widened receipt audience")
		}
	})
	t.Run("current currency mismatch never borrows another record", func(t *testing.T) {
		src := source()
		x := newFixture(t, d, src)
		x.record(t, f.Actor(f.Subject))
		input := x.input(t, 32, big.NewInt(2e18), x.token, f.Org, false)
		check(t, x.one, input, true)
		for i := range src.Organizations {
			src.Organizations[i].Spec.Settings.Currency = "eur"
			src.Organizations[i].Spec.TokenPrices[0].PricesByCurrency = map[string]float64{"eur": 1}
		}
		x.snapshot = f.ComplianceSnapshot(t, src)
		x.admin = f.Token(t, x.snapshot, f.AdminSubject, "Admin")
		x.token = f.Token(t, x.snapshot, f.Subject, "Auditor")
		x.one = x.service(t, d.one, nil)
		resp, err := x.one.CreateRecord(t.Context(), x.admin, f.Org, createRequest(f.Actor(f.Subject)))
		if err != nil {
			t.Fatal(err)
		}
		var discard bytes.Buffer
		if _, err := resp.WriteTo(&discard); err != nil {
			t.Fatal(err)
		}
		input = x.input(t, 32, big.NewInt(2e18), x.token, f.Org, false)
		check(t, x.one, input, false)
		var unused int
		if err := d.owner.QueryRow(t.Context(), `SELECT count(*)FROM ops_admission_v2.travel_records WHERE network_key=$1 AND used_at IS NULL AND currency='eur'`, x.key[:]).Scan(&unused); err != nil || unused != 1 {
			t.Fatal("currency borrowed record", err)
		}
	})
	t.Run("current source sanctions deny without claiming unused record", func(t *testing.T) {
		src := source()
		src.Sanctions = []compliancepolicy.SourceSanction{{ID: uuid.NewString(), Scope: "global", OrganizationID: "", Address: createRequest("").BeneficiaryAddress, Reason: "fixture sanctioned beneficiary", Source: "fixture"}}
		x := newFixture(t, d, src)
		record := x.record(t, f.Actor(f.Subject))
		input := x.input(t, 33, big.NewInt(2e18), x.token, f.Org, true)
		check(t, x.one, input, false)
		checkUnused(t, x, record.ID)
		if count(t, x, "qualified_tx_origins") != 0 || count(t, x, "compliance_events") != 1 {
			t.Fatal("sanctioned privacy effects")
		}
	})
	t.Run("same witness preserves first metadata and later witnesses are capped", func(t *testing.T) {
		src := source()
		for i := range src.Organizations {
			src.Organizations[i].Spec.Settings.Enabled = false
		}
		x := newFixture(t, d, src)
		input := x.input(t, 34, big.NewInt(0), x.token, f.Org, true)
		check(t, x.one, input, true)
		x.clock.Store(f.Now + 1)
		check(t, x.two, input, true)
		var first time.Time
		if err := d.owner.QueryRow(t.Context(), `SELECT decision_at FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1`, x.key[:]).Scan(&first); err != nil || first.Unix() != f.Now {
			t.Fatal("first witness overwritten", err)
		}
		anchor := input.Execution.Anchor()
		ids, versions := [][]byte{}, [][]byte{}
		for i := 0; i < a.MaxWitnesses-1; i++ {
			version := a.HashParts("fixture-wallet", []byte(uuid.NewString()))
			w := a.Witness{AnchorHash: anchor.Hash, EvidenceProfile: anchor.Profile, WalletVersion: version}
			w.ID = w.Digest()
			ids = append(ids, bytes.Clone(w.ID[:]))
			versions = append(versions, bytes.Clone(version[:]))
		}
		if _, err := d.owner.Exec(t.Context(), `INSERT INTO ops_admission_v2.extra_privacy_witnesses(network_key,tx_hash,witness_id,anchor_hash,anchor_number,anchor_timestamp,evidence_profile,wallet_version,decision_at,manifest_digest,compliance_digest,wallet_evidence_at)SELECT o.network_key,o.tx_hash,v.id,o.anchor_hash,o.anchor_number,o.anchor_timestamp,o.evidence_profile,v.version,o.decision_at,o.manifest_digest,o.compliance_digest,o.wallet_evidence_at FROM ops_admission_v2.qualified_tx_origins o CROSS JOIN unnest($2::bytea[],$3::bytea[])v(id,version)WHERE o.network_key=$1`, x.key[:], ids, versions); err != nil {
			t.Fatal(err)
		}
		version := a.HashParts("fixture-over-cap")
		snapshot, err := nativeadmission.NewWalletSnapshot(input.View.ActorID(), version.String(), time.Unix(f.Now, 0).UTC(), []common.Address{input.Transaction.Signer()})
		if err != nil {
			t.Fatal(err)
		}
		over := input
		over.WalletSnapshot = snapshot
		if result, err := x.one.CheckAndRecordRaw(t.Context(), over); !errors.Is(err, a.ErrConflict) || result != nil {
			t.Fatal("witness cap", err)
		}
		if count(t, x, "extra_privacy_witnesses") != a.MaxWitnesses-1 {
			t.Fatal("witness overflow")
		}
		// A duplicate of the inline primary stays admissible even at the cap.
		check(t, x.two, input, true)
	})
	t.Run("HTTP construction rejects missing cursor keys", func(t *testing.T) {
		x := newFixture(t, d, source())
		s, err := a.New(a.Config{Snapshot: x.snapshot, Clock: func() time.Time { return time.Unix(f.Now, 0).UTC() }, NetworkBinding: x.binding, ExpectedState: x.state, Store: d.one, ExpectedEvidenceProfile: rpcexecution.GuardRetainedProfileID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := compliancehttp.New(s); !errors.Is(err, a.ErrInvalid) {
			t.Fatal("keyless admin HTTP", err)
		}
	})
	t.Run("missing expected index or disabled immutability trigger blocks startup", func(t *testing.T) {
		if _, err := d.owner.Exec(t.Context(), `DROP INDEX ops_admission_v2.travel_scoped_used_hash`); err != nil {
			t.Fatal(err)
		}
		bad, err := admissionsql.Open(t.Context(), d.appDSN)
		if bad != nil {
			bad.Close()
		}
		if err == nil {
			t.Fatal("missing unique index accepted")
		}
		if _, err := d.owner.Exec(t.Context(), `CREATE UNIQUE INDEX travel_scoped_used_hash ON ops_admission_v2.travel_records(network_key,org_id,actor_id,used_tx_hash)WHERE used_at IS NOT NULL`); err != nil {
			t.Fatal(err)
		}
		if _, err := d.owner.Exec(t.Context(), `ALTER TABLE ops_admission_v2.travel_records DISABLE TRIGGER travel_record_monotonic`); err != nil {
			t.Fatal(err)
		}
		bad, err = admissionsql.Open(t.Context(), d.appDSN)
		if bad != nil {
			bad.Close()
		}
		if err == nil {
			t.Fatal("disabled trigger accepted")
		}
		if _, err := d.owner.Exec(t.Context(), `ALTER TABLE ops_admission_v2.travel_records ENABLE TRIGGER travel_record_monotonic`); err != nil {
			t.Fatal(err)
		}
	})
}

func createBeneficiary() [20]byte { var out [20]byte; out[19] = 2; return out }
