package rpcengine_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/transactioninput"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
	"privacy-proxy/internal/walletproof"
)

type rawDatabase struct {
	ownerDSN, appDSN, walletDSN string
	owner                       *pgx.Conn
}

// These faults wrap a REAL completed PostgreSQL transaction. They cannot mint
// a receipt; the service must treat an ambiguous return as unpublished intent.
type rawCommitFaults struct {
	admission.Store
	ambiguous     atomic.Bool
	expire        atomic.Bool
	quoteExpire   atomic.Bool
	onExpire      func()
	onQuoteExpire func()
}

func (s *rawCommitFaults) WithRawTransaction(ctx context.Context, scope admission.Scope, callback func(admission.RawTx) (admission.CommitKind, error)) (admission.CommitReceipt, error) {
	receipt, err := s.Store.WithRawTransaction(ctx, scope, callback)
	if err == nil && receipt.Committed && receipt.Kind == admission.CommitAllow {
		if s.ambiguous.Swap(false) {
			return admission.CommitReceipt{}, admission.ErrUnavailable
		}
		if s.expire.Swap(false) {
			s.onExpire()
		}
		if s.quoteExpire.Swap(false) {
			s.onQuoteExpire()
		}
	}
	return receipt, err
}

type currentQuotes struct{ clock func() time.Time }

func (q currentQuotes) Capture(context.Context) (admission.QuoteSnapshot, error) {
	now := q.clock()
	return admission.NewQuoteSnapshot([]admission.Quote{{ID: "ethereum", Currency: "usd", Value: 1, FetchedAt: now, ProviderAsOf: now, SourceID: "owned-test-feed"}})
}

func rawPostgres(t *testing.T) rawDatabase {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("raw operational qualification requires Docker PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=raw-test-only", "--env", "POSTGRES_DB=raw_test", "--name", "ops-v2-raw-test-"+uuid.NewString()[:8], "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("owned PostgreSQL: %v %s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if out, err := exec.CommandContext(c, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Logf("owned PostgreSQL cleanup %v %s", err, out)
		}
	})
	out, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	d := rawDatabase{ownerDSN: "postgres://postgres:raw-test-only@" + strings.TrimSpace(string(out)) + "/raw_test?sslmode=disable"}
	for ctx.Err() == nil {
		d.owner, err = pgx.Connect(ctx, d.ownerDSN)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		d.owner.Close(c)
	})
	for _, role := range []string{"raw_app", "raw_reader", "raw_retention", "wallet_app", "wallet_reader", "wallet_retention"} {
		if _, err := d.owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'raw-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if err := admissionsql.Migrate(t.Context(), d.ownerDSN, "raw_app", "raw_reader", "raw_retention"); err != nil {
		t.Fatal(err)
	}
	if err := walletsql.Migrate(t.Context(), d.ownerDSN, "wallet_app", "wallet_reader", "wallet_retention"); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(d.ownerDSN)
	u.User = url.UserPassword("raw_app", "raw-test-only")
	d.appDSN = u.String()
	u.User = url.UserPassword("wallet_app", "raw-test-only")
	d.walletDSN = u.String()
	return d
}

func materialize(t *testing.T, response interface {
	WriteTo(io.Writer) (int64, error)
}) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := response.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func signedValue(t *testing.T, nonce uint64) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	tx, err := types.SignTx(types.NewTransaction(nonce, common.HexToAddress(addressA), new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)), 100000, big.NewInt(1), []byte{1, 2}), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	v, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func operationalLink(t *testing.T, service *walletops.Service, token string, address common.Address) {
	t.Helper()
	response, err := service.Issue(t.Context(), token, walletops.ChallengeRequest{Address: address.Hex()})
	if err != nil {
		t.Fatal(err)
	}
	var challenge walletops.ChallengeResult
	if json.Unmarshal(materialize(t, response), &challenge) != nil || challenge.Message == "" {
		t.Fatal("challenge missing")
	}
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	signature, err := crypto.Sign(walletproof.HashMessage(challenge.Message), key)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.Verify(t.Context(), token, walletops.VerifyRequest{Nonce: challenge.Nonce, Address: address.Hex(), Signature: "0x" + hex.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	materialize(t, response)
}

func rawHTTP(t *testing.T, server *httptest.Server, token string, tx transactioninput.VerifiedTransaction, audience []string) rpcengine.Response {
	t.Helper()
	m := map[string]any{"jsonrpc": "2.0", "id": "checked-raw", "method": "eth_sendRawTransaction", "params": []any{tx.RawHex()}}
	if audience != nil {
		m["visibleTo"] = audience
	}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, bytes.NewReader(encoded(t, m)))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	var out rpcengine.Response
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal(string(raw))
	}
	return out
}

type admissionCounts struct{ used, allowed, denied, origins, shares int }

func rawCounts(t *testing.T, d rawDatabase, network admission.Digest, hash common.Hash) admissionCounts {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var c admissionCounts
	err := d.owner.QueryRow(ctx, `SELECT
 (SELECT count(*)FROM ops_admission_v2.travel_records WHERE network_key=$1 AND used_tx_hash=$2),
 (SELECT count(*)FROM ops_admission_v2.compliance_events WHERE network_key=$1 AND tx_hash=$2 AND decision='allowed'),
 (SELECT count(*)FROM ops_admission_v2.compliance_events WHERE network_key=$1 AND tx_hash=$2 AND decision='denied'),
 (SELECT count(*)FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1 AND tx_hash=$2),
 (SELECT count(*)FROM ops_admission_v2.tx_shares WHERE network_key=$1 AND tx_hash=$2)`, network[:], hash[:]).Scan(&c.used, &c.allowed, &c.denied, &c.origins, &c.shares)
	if err != nil {
		t.Fatal("bounded commit oracle", err)
	}
	return c
}

func TestBothRawModesCommitRealFinancialAndPrivacyEffectsBeforePublication(t *testing.T) {
	d := rawPostgres(t)
	for _, mode := range []string{policybundle.RawSubmissionOPSPreflight, policybundle.RawSubmissionGuardV1} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture()
			f.rawMode = mode
			f.groups[0].AllowedMethods = []string{"eth_call", "eth_sendTransaction"}
			f.groups[0].IsOrgAdmin = true
			f.capability("operational.travel-rule/v1")
			f.capability("inputs.price-quotes/v1")
			f.complianceHook = func(source *compliancepolicy.Source) {
				for i := range source.Organizations {
					o := &source.Organizations[i]
					o.RecordMaxSeconds = 30
					o.PriceMaxAgeSeconds = 10
					o.Spec.Settings = compliancepolicy.SourceSettings{Enabled: true, Currency: "usd", ThresholdFiat: 1, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}
					o.Spec.TokenPrices = []compliancepolicy.SourceTokenPrice{{ID: "dddddddd-dddd-4ddd-8ddd-" + strings.Repeat("0", 11) + string(rune('1'+i)), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{}, CoingeckoID: "ethereum"}}
				}
			}
			snapshot := f.load(t)
			var instant atomic.Int64
			instant.Store(now)
			clock := func() time.Time { return time.Unix(instant.Load(), 0) }
			tok := token(t, snapshot, f.roles)
			binding := walletops.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: nodeHash, DeploymentID: "raw-pg-" + mode}
			network := admission.NetworkBinding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}
			walletGeneration, generation := uuid.NewString(), uuid.NewString()
			if err := walletsql.BootstrapEmpty(t.Context(), d.ownerDSN, binding, walletGeneration); err != nil {
				t.Fatal(err)
			}
			if err := admissionsql.BootstrapEmpty(t.Context(), d.ownerDSN, network, generation); err != nil {
				t.Fatal(err)
			}
			walletStore, err := walletsql.Open(t.Context(), d.walletDSN)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(walletStore.Close)
			store, err := admissionsql.Open(t.Context(), d.appDSN)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(store.Close)
			walletState := walletops.ExpectedState{Generation: walletGeneration, Coverage: walletsql.EmptyCoverage()}
			walletService, err := walletops.New(walletops.Config{Snapshot: snapshot, Clock: clock, Binding: binding, State: walletState, Store: walletStore})
			if err != nil {
				t.Fatal(err)
			}
			first := signedValue(t, 9)
			operationalLink(t, walletService, tok, first.Signer())
			namespace, _ := binding.Namespace()
			resolver, err := walletadapter.New(walletStore, namespace, walletState, clock)
			if err != nil {
				t.Fatal(err)
			}
			profile := rpcexecution.SignedCallProfileID
			if mode == policybundle.RawSubmissionGuardV1 {
				profile = rpcexecution.GuardRetainedProfileID
			}
			faults := &rawCommitFaults{Store: store, onExpire: func() { instant.Store(now + 300) }, onQuoteExpire: func() { instant.Store(now + 42) }}
			financial, err := admission.New(admission.Config{Snapshot: snapshot, Clock: clock, NetworkBinding: network, ExpectedState: admission.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}, Store: faults, ExpectedEvidenceProfile: profile, QuoteProvider: currentQuotes{clock: clock}})
			if err != nil {
				t.Fatal(err)
			}
			factory, _ := runtimepolicy.NewFactory(snapshot, clock)
			view, err := factory.Build(tok)
			if err != nil {
				t.Fatal(err)
			}
			createRecord := func() {
				response, err := financial.CreateRecord(t.Context(), tok, orgA, admission.CreateRecordRequest{OriginatorActorID: view.ActorID(), OriginatorData: json.RawMessage(`{"name":"origin"}`), BeneficiaryData: json.RawMessage(`{"name":"beneficiary"}`), TransferType: compliance.TransferTypeETH, BeneficiaryAddress: addressA, AmountWei: "3000000000000000000"})
				if err != nil {
					t.Fatal("real record administration", err)
				}
				materialize(t, response)
			}
			createRecord()
			n := &node{}
			nodeServer := httptest.NewServer(n)
			t.Cleanup(nodeServer.Close)
			var publications atomic.Int64
			var expectShare, wrongHash atomic.Bool
			n.onSend = func(raw string) string {
				tx, err := transactioninput.DecodeRaw(raw, "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
				if err != nil {
					t.Error("node got altered bytes", err)
					return common.Hash{}.Hex()
				}
				c := rawCounts(t, d, financial.Metadata().NetworkKey, tx.Hash())
				if c.used != 1 || c.allowed < 1 || c.origins != 1 || (expectShare.Load() && c.shares != 1) {
					t.Error("publication preceded atomic claim/audit/origin/share COMMIT", c)
				}
				publications.Add(1)
				if wrongHash.Load() {
					return common.Hash{}.Hex()
				}
				return tx.Hash().Hex()
			}
			callClients := map[string]*rpcexecution.Client{}
			for _, org := range []string{orgA, orgB} {
				c, err := rpcexecution.NewClient(nodeServer.Client().Transport, rpcexecution.NodeBinding{OrganizationID: org, URL: nodeServer.URL, ChainID: "1", Profile: rpcexecution.NodeProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				callClients[org] = c
			}
			rawNode := rpcengine.RawNodeOptions{Binding: rpcexecution.NodeBinding{OrganizationID: orgA, URL: nodeServer.URL, ChainID: "1", Profile: profile, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, Transport: nodeServer.Client().Transport, Limits: rpcexecution.DefaultLimits()}
			var producer *faultProducer
			if mode == policybundle.RawSubmissionGuardV1 {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				producer = &faultProducer{batches: make(chan []byte, 16)}
				server := grpc.NewServer()
				approvalpb.RegisterApprovalDeliveryServer(server, producer)
				go server.Serve(listener)
				t.Cleanup(server.Stop)
				rawNode.HashMode = nodeapproval.HashCalls
				rawNode.Seed = bytes.Repeat([]byte{7}, 32)
				rawNode.KeyID = "pair-key"
				rawNode.MaxBatch = 32
				rawNode.Delivery = nodeapproval.DeliveryOptions{Targets: []string{listener.Addr().String()}, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}
			}
			engine, err := rpcengine.NewRaw(snapshot, rpcengine.RawOptions{CallClients: callClients, RawNodes: map[string]rpcengine.RawNodeOptions{orgA: rawNode}, Wallets: resolver, WalletBinding: binding, WalletState: walletState, Admission: financial, Clock: clock})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(engine.Close)
			server := httptest.NewServer(engine.Handler(orgA))
			t.Cleanup(server.Close)
			// A test CLIENT repeats only a known preflight readiness refusal with
			// zero node work. It never retries an ambiguous/accepted submission.
			deadline := time.Now().Add(3 * time.Second)
			for {
				out := rawHTTP(t, server, tok, first, nil)
				if out.Error == nil {
					if out.Result == nil || *out.Result != first.Hash().Hex() {
						t.Fatal(out)
					}
					break
				}
				methods, _ := n.counts()
				if mode != policybundle.RawSubmissionGuardV1 || out.Error.Code != -32002 || len(methods) != 0 || time.Now().After(deadline) {
					t.Fatal("real raw admission failed", out)
				}
				time.Sleep(2 * time.Millisecond)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, first.Hash()); c.used != 1 || c.allowed != 1 || c.origins != 1 || c.shares != 0 {
				t.Fatal(c)
			}
			instant.Store(now + 31)
			expectShare.Store(true)
			audience := []string{view.ActorID()}
			out := rawHTTP(t, server, tok, first, audience)
			if out.Error != nil {
				t.Fatal("used record expiry/first-nonempty retry failed", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, first.Hash()); c.used != 1 || c.allowed != 2 || c.shares != 1 {
				t.Fatal("retry duplicated claim or lost first share", c)
			}
			otherAudience := "ops:p1:" + strings.Repeat("A", 43)
			out = rawHTTP(t, server, tok, first, []string{otherAudience})
			if out.Error == nil || out.Error.Code != -32001 || publications.Load() != 2 {
				t.Fatal("first nonempty share broadened", out)
			}
			denied := signedValue(t, 10)
			out = rawHTTP(t, server, tok, denied, nil)
			if out.Error == nil || out.Error.Code != -32003 {
				t.Fatal("real compliance deny lost", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, denied.Hash()); c.used != 0 || c.denied != 1 || c.origins != 0 || c.shares != 0 {
				t.Fatal("deny was rolled back or created authority", c)
			}
			createRecord()
			faulted := signedValue(t, 11)
			if _, err := d.owner.Exec(t.Context(), `REVOKE INSERT ON ops_admission_v2.compliance_events FROM raw_app`); err != nil {
				t.Fatal(err)
			}
			out = rawHTTP(t, server, tok, faulted, audience)
			if _, err := d.owner.Exec(t.Context(), `GRANT INSERT ON ops_admission_v2.compliance_events TO raw_app`); err != nil {
				t.Fatal(err)
			}
			if out.Error == nil || out.Error.Code != -32002 || publications.Load() != 2 {
				t.Fatal("required audit fault published", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, faulted.Hash()); c != (admissionCounts{}) {
				t.Fatal("partial effects survived audit failure", c)
			}
			out = rawHTTP(t, server, tok, faulted, audience)
			if out.Error != nil || publications.Load() != 3 {
				t.Fatal("fresh retry after rollback failed", out)
			}
			createRecord()
			unknown := signedValue(t, 12)
			wrongHash.Store(true)
			out = rawHTTP(t, server, tok, unknown, audience)
			if out.Error == nil || out.Error.Code != -32004 || publications.Load() != 4 {
				t.Fatal("wrong node hash reported rejection/success", out)
			}
			data, ok := out.Error.Data.(map[string]any)
			if !ok || data["transactionHash"] != unknown.Hash().Hex() {
				t.Fatal("unknown outcome lacks verified reconciliation hash", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, unknown.Hash()); c.used != 1 || c.allowed != 1 || c.origins != 1 || c.shares != 1 {
				t.Fatal("unknown result erased committed intent", c)
			}
			wrongHash.Store(false)
			createRecord()
			ambiguous := signedValue(t, 13)
			faults.ambiguous.Store(true)
			out = rawHTTP(t, server, tok, ambiguous, audience)
			if out.Error == nil || out.Error.Code != -32002 || publications.Load() != 4 {
				t.Fatal("unknown SQL COMMIT minted publication receipt", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, ambiguous.Hash()); c.used != 1 || c.allowed != 1 || c.origins != 1 || c.shares != 1 {
				t.Fatal("test did not create actual committed-unsent intent", c)
			}
			out = rawHTTP(t, server, tok, ambiguous, audience)
			if out.Error != nil || publications.Load() != 5 {
				t.Fatal("fresh client retry after SQL ambiguity failed", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, ambiguous.Hash()); c.used != 1 || c.allowed != 2 {
				t.Fatal("SQL ambiguity retry consumed another record", c)
			}
			createRecord()
			quoteExpired := signedValue(t, 14)
			faults.quoteExpire.Store(true)
			out = rawHTTP(t, server, tok, quoteExpired, audience)
			if out.Error == nil || out.Error.Code != -32002 || publications.Load() != 5 {
				t.Fatal("stale used positive quote reached publication", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, quoteExpired.Hash()); c.used != 1 || c.allowed != 1 || c.origins != 1 {
				t.Fatal("post-COMMIT quote intent not durable", c)
			}
			createRecord()
			expired := signedValue(t, 15)
			faults.expire.Store(true)
			out = rawHTTP(t, server, tok, expired, audience)
			if out.Error == nil || out.Error.Code != -32001 || publications.Load() != 5 {
				t.Fatal("expired post-COMMIT view reached first external effect", out)
			}
			if c := rawCounts(t, d, financial.Metadata().NetworkKey, expired.Hash()); c.used != 1 || c.allowed != 1 || c.origins != 1 || c.shares != 1 {
				t.Fatal("committed-unsent expiry intent was lost", c)
			}
			if producer != nil {
				deadline := time.Now().Add(3 * time.Second)
				for producer.approvals.Load() < 5 && time.Now().Before(deadline) {
					time.Sleep(2 * time.Millisecond)
				}
				if producer.approvals.Load() != 5 {
					t.Fatal("queue count includes failed/denied requests", producer.approvals.Load())
				}
				engine.Close()
				for len(producer.batches) > 0 {
					verifyRawBatch(t, <-producer.batches, map[common.Hash]bool{first.Hash(): true, faulted.Hash(): true, unknown.Hash(): true, ambiguous.Hash(): true})
				}
			}
			time.Sleep(25 * time.Millisecond)
			if publications.Load() != 5 {
				t.Fatal("automatic raw rebroadcast")
			}
		})
	}
}

func verifyRawBatch(t *testing.T, raw []byte, allowed map[common.Hash]bool) {
	t.Helper()
	if len(raw) < 64 {
		t.Fatal("unsigned Guard batch")
	}
	message, signature := raw[:len(raw)-64], raw[len(raw)-64:]
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("bad original Guard signature")
	}
	prefix := []byte("OPS_APPROVAL_BATCH_V2\x00")
	if !bytes.HasPrefix(message, prefix) || len(message) <= len(prefix) {
		t.Fatal("wire domain")
	}
	offset := len(prefix)
	offset += 1 + int(message[offset])
	if len(message) < offset+20 {
		t.Fatal("short wire batch")
	}
	issued, expires := binary.BigEndian.Uint64(message[offset:]), binary.BigEndian.Uint64(message[offset+8:])
	count := int(binary.BigEndian.Uint32(message[offset+16:]))
	offset += 20
	if expires-issued != uint64(nodeapproval.DefaultApprovalTTL.Milliseconds()) {
		t.Fatal("Guard TTL capped by JWT/record expiry")
	}
	itemPrefix := []byte("OPS_APPROVAL_V3\x00")
	size := len(itemPrefix) + 8 + 32 + 32 + 32
	if len(message)-offset != count*size {
		t.Fatal("invalid item count")
	}
	for i := 0; i < count; i++ {
		item := message[offset+i*size : offset+(i+1)*size]
		if !bytes.HasPrefix(item, itemPrefix) || binary.BigEndian.Uint64(item[len(itemPrefix):]) != 1 {
			t.Fatal("approval mode/chain changed")
		}
		at := len(itemPrefix) + 8
		hash := common.BytesToHash(item[at : at+32])
		if !allowed[hash] || bytes.Equal(item[at+32:at+64], make([]byte, 32)) || !bytes.Equal(item[at+64:], make([]byte, 32)) {
			t.Fatal("uncommitted/rewritten/reserved-principal approval")
		}
	}
}
