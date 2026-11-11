package activitylog_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpchistorypolicy"
	"privacy-proxy/internal/rpcmetadatapolicy"
)

// One finite bridge crosses actual wallet proof+restricted reader, actual
// immutable share writer+readonly reader, actual TLS node, actual synced Pebble
// Append and actual activity SQL. The node remains a protocol fixture.
func TestHistoryRPCActualPGWalletSharesRecorderAndFinalGates(t *testing.T) {
	d := rawPostgres(t)
	ctx := t.Context()
	for _, role := range []string{"history_observer", "history_facts"} {
		if _, err := d.owner.Exec(ctx, `CREATE ROLE `+role+` LOGIN NOINHERIT PASSWORD 'raw-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if err := admissionsql.MigrateCreationObserver(ctx, d.ownerDSN, "raw_app", "raw_reader", "raw_retention", "history_observer", "history_facts"); err != nil {
		t.Fatal(err)
	}
	target := common.HexToAddress("0x123456")
	txs := []*types.Transaction{f.HistoryTransaction(t, 1, 0, target), f.HistoryTransaction(t, 2, 1, target)}
	node := f.NewHistoryNode(t, txs, [][]*types.Log{{}, {}})
	network := node.Network()
	var instant atomic.Int64
	instant.Store(f.Now)
	clock := func() time.Time { return time.Unix(instant.Load(), 0) }
	src := f.DefaultStateFixture(t)
	src.HistoryConsumer = true
	contract := f.ReadContract(target.Hex())
	src.Contracts[f.Org] = []policybundle.Contract{contract}
	snapshot := f.StateSnapshot(t, src)
	tok := f.Token(t, snapshot, f.Subject, "Auditor")
	if _, err := d.owner.Exec(ctx, `CREATE DATABASE history_wallet_test`); err != nil {
		t.Fatal(err)
	}
	walletURL, _ := url.Parse(d.ownerDSN)
	walletURL.Path = "/history_wallet_test"
	wallet := f.ActualWalletFixture(t, ctx, walletURL.String(), snapshot, network, clock)
	wallet.Link(t, ctx, tok, f.HistoryKey(1))
	state := a.ExpectedState{Generation: uuid.NewString(), Coverage: admissionsql.EmptyCoverage()}
	nb := a.NetworkBinding{Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.GenesisHash, DeploymentID: network.DeploymentID}
	if err := admissionsql.BootstrapEmpty(ctx, d.ownerDSN, nb, state.Generation); err != nil {
		t.Fatal(err)
	}
	app, err := admissionsql.Open(ctx, d.appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	readerURL, _ := url.Parse(d.ownerDSN)
	readerURL.User = url.UserPassword("raw_reader", "raw-test-only")
	readerStore, err := admissionsql.OpenReader(ctx, readerURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readerStore.Close)
	shareBinding := historyfacts.ShareBinding{Network: network, State: state, SchemaProfile: historyfacts.ShareSchemaProfile}
	shares, err := admissionsql.NewShareReader(readerStore, shareBinding)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := nb.Key()
	recipients, digest, _ := a.NormalizeRecipients([]string{f.Actor(f.Subject)})
	scope := a.Scope{Network: key, Hash: txs[1].Hash(), Actor: f.Actor(f.AdminSubject), Organization: f.Org, State: state}
	share := a.Share{Network: key, Hash: scope.Hash, Actor: scope.Actor, Organization: scope.Organization, Recipients: recipients, RecipientDigest: digest, DeclaredAt: clock(), Witness: a.Witness{AnchorHash: node.Hash(), AnchorNumber: 1, AnchorTimestamp: uint64(f.Now), ManifestDigest: a.Digest{2}, WalletVersion: a.Digest{3}, WalletEvidenceAt: clock()}}
	receipt, err := app.WithRawTransaction(ctx, scope, func(tx a.RawTx) (a.CommitKind, error) { return a.CommitAllow, tx.PutShare(share) })
	if err != nil || !receipt.Committed {
		t.Fatal("actual immutable share commit", err)
	}
	policyRaw, _ := json.Marshal(rpchistorypolicy.Source{APIVersion: rpchistorypolicy.APIVersion, Kind: rpchistorypolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}})
	policy, err := rpchistorypolicy.Compile(policyRaw, rpchistorypolicy.Digest(sha256.Sum256(policyRaw)))
	if err != nil {
		t.Fatal(err)
	}
	limits := rpcexecution.DefaultHistoryReadLimits()
	client := func(org string) *rpcexecution.HistoryReadClient {
		c, err := rpcexecution.NewHistoryReadClient(node.Transport(), node.Source(org), rpcexecution.Credential{}, limits)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	history, err := rpcengine.NewHistory(rpcengine.HistoryConfig{Snapshot: snapshot, Policy: policy, Network: network, Default: client(""), Clients: map[rpcengine.HistoryBindingKey]*rpcexecution.HistoryReadClient{{OrganizationID: f.Org}: client(f.Org), {OrganizationID: f.OtherOrg}: client(f.OtherOrg)}, Wallets: wallet.Resolver, WalletBinding: wallet.Binding, WalletState: wallet.State, Shares: shares, ShareExpected: shareBinding, QueryLimits: limits, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	metadataRaw, _ := json.Marshal(rpcmetadatapolicy.Source{APIVersion: rpcmetadatapolicy.APIVersion, Kind: rpcmetadatapolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}})
	metadataPolicy, err := rpcmetadatapolicy.Compile(metadataRaw, rpcmetadatapolicy.Digest(sha256.Sum256(metadataRaw)))
	if err != nil {
		t.Fatal(err)
	}
	metaClient, err := rpcexecution.NewMetadataClient(node.Transport(), rpcexecution.MetadataSource{Network: network, URL: node.Source("").URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultMetadataLimits())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := rpcengine.NewMetadata(rpcengine.MetadataConfig{Snapshot: snapshot, Policy: metadataPolicy, Network: network, Default: metaClient, Clients: map[rpcengine.MetadataBindingKey]*rpcexecution.MetadataClient{{OrganizationID: f.Org}: metaClient, {OrganizationID: f.OtherOrg}: metaClient}, QueryLimits: rpcexecution.DefaultMetadataLimits(), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	activity := setupActivityDatabase(t, network)
	methods := append(history.OperationBinding().Methods, metadata.OperationBinding().Methods...)
	for _, scenario := range []string{"listed-positive-and-shared-N", "source-change-during-append", "share-change-during-append", "expiry-during-append", "append-failure", "unlink-during-append"} {
		t.Run(scenario, func(t *testing.T) {
			instant.Store(f.Now)
			node.Reorg(false)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			hook := func(uint64) error {
				close(entered)
				<-release
				if scenario == "append-failure" {
					return errors.New("test-owned actual Pebble fault")
				}
				return nil
			}
			recorder := rpcRecorder(t, activity, clock, hook, methods...)
			if _, err := rpcactivity.New(rpcactivity.Config{Metadata: metadata, Recorder: recorder, Network: network}); err == nil {
				t.Fatal("history-required snapshot served by sibling alone")
			}
			service, err := rpcactivity.New(rpcactivity.Config{History: history, Metadata: metadata, Recorder: recorder, Network: network})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := service.Handler(f.Org)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			method, params := "eth_getTransactionByHash", `["`+txs[1].Hash().Hex()+`"]`
			if scenario == "source-change-during-append" {
				method, params = "eth_getBlockByNumber", `["0x1",true]`
			}
			var beforeRows int64
			if err := activity.owner.QueryRow(ctx, `SELECT count(*) FROM public.access_logs WHERE activity_kind=1 AND method=$1`, method).Scan(&beforeRows); err != nil {
				t.Fatal(err)
			}
			body := `{"jsonrpc":"2.0","id":"published","method":"` + method + `","params":` + params + `}`
			done := requestAsync(t, server.Client(), server.URL, tok, body, t.Context())
			await(t, entered)
			select {
			case <-done:
				t.Fatal("HTTP output before actual synced Append")
			default:
			}
			switch scenario {
			case "listed-positive-and-shared-N":
				before := node.Calls()["eth_chainId"]
				busy := requestAsync(t, server.Client(), server.URL, tok, `{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}`, t.Context())
				b := bodyResult(t, busy)
				if !bytes.Contains(b, []byte("unavailable")) || node.Calls()["eth_chainId"] != before {
					t.Fatal("metadata escaped same N during history Append", string(b))
				}
			case "source-change-during-append":
				node.Reorg(true)
			case "share-change-during-append":
				if _, err := d.owner.Exec(ctx, `UPDATE ops_admission_v2.tx_shares SET anchor_timestamp=anchor_timestamp+1 WHERE network_key=$1 AND tx_hash=$2`, key[:], scope.Hash[:]); err != nil {
					t.Fatal(err)
				}
			case "expiry-during-append":
				instant.Store(f.Now + 300)
			case "unlink-during-append":
				if _, err := wallet.Service.Unlink(ctx, tok, crypto.PubkeyToAddress(f.HistoryKey(1).PublicKey).Hex()); err != nil {
					t.Fatal(err)
				}
			}
			once.Do(func() { close(release) })
			out := bodyResult(t, done)
			if scenario == "listed-positive-and-shared-N" {
				if !bytes.Contains(out, []byte(txs[1].Hash().Hex())) || bytes.Contains(out, []byte(`"error"`)) {
					t.Fatal("actual share did not admit full RPC transaction", string(out))
				}
			} else if bytes.Contains(out, []byte(`"result"`)) || !bytes.Contains(out, []byte("unavailable")) {
				t.Fatal("protected output after failed final/Append gate", scenario, string(out))
			}
			if scenario == "share-change-during-append" {
				if _, err := d.owner.Exec(ctx, `UPDATE ops_admission_v2.tx_shares SET anchor_timestamp=anchor_timestamp-1 WHERE network_key=$1 AND tx_hash=$2`, key[:], scope.Hash[:]); err != nil {
					t.Fatal(err)
				}
			}
			instant.Store(f.Now)
			node.Reorg(false)
			if scenario != "append-failure" {
				until := time.Now().Add(2 * time.Second)
				var rows int64
				for time.Now().Before(until) {
					if err := activity.owner.QueryRow(ctx, `SELECT count(*) FROM public.access_logs WHERE activity_kind=1 AND method=$1`, method).Scan(&rows); err != nil {
						t.Fatal(err)
					}
					if rows >= beforeRows+1 {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if rows != beforeRows+1 {
					t.Fatal("actual sealed activity completion count", rows, beforeRows)
				}
			}
		})
	}
}
