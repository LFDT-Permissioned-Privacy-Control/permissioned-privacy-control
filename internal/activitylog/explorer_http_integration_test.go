package activitylog_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"privacy-proxy/internal/activitymethoddata"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/explorerquery"
	wire "privacy-proxy/internal/explorerv2data"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/indexertest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/explorerindex"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpchistorypolicy"
	"privacy-proxy/internal/rpcmetadatapolicy"
	"privacy-proxy/internal/rpcstatepolicy"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExplorerActualWalletShareIndexNodeAndOneRecorderHTTP(t *testing.T) {
	testExplorerActualHTTP(t, false, "standard")
}
func TestExplorerActualPrunedNodePointsPrivacyAndFinalReorgHTTP(t *testing.T) {
	testExplorerActualHTTP(t, true, "standard")
}
func TestExplorerActualTransferKindFilterCursorAndCurrentRightsHTTP(t *testing.T) {
	testExplorerActualHTTP(t, false, "standard", true)
}
func TestExplorerActualStrictCountPopulations(t *testing.T) {
	testExplorerActualHTTP(t, false, "strict")
}
func TestExplorerActualCountBudgetPastOneSourcePage(t *testing.T) {
	testExplorerActualHTTP(t, false, "large")
}
func TestExplorerActualCountsKeepOriginalMethodGates(t *testing.T) {
	testExplorerActualHTTP(t, false, "no-logs")
}
func TestExplorerActualSlowOptionalCountKeepsShortBasePurpose(t *testing.T) {
	testExplorerActualHTTP(t, false, "slow")
}
func TestExplorerActualExpiredIdentityNeverPublishesCounts(t *testing.T) {
	testExplorerActualHTTP(t, false, "expiry")
}
func TestExplorerActualFailedOptionalCountRecheckKeepsPage(t *testing.T) {
	testExplorerActualHTTP(t, false, "recheck")
}
func TestExplorerActualBlockCountsStandardAndEmptyGroup(t *testing.T) {
	testExplorerActualHTTP(t, false, "block-standard")
}
func TestExplorerActualBlockCountsStrict(t *testing.T) {
	testExplorerActualHTTP(t, false, "block-strict")
}
func TestExplorerActualBlockCountsMethodGate(t *testing.T) {
	testExplorerActualHTTP(t, false, "block-no-tx")
}
func TestExplorerActualBlockCountsBudgetCutoff(t *testing.T) {
	testExplorerActualHTTP(t, false, "block-large")
}
func testExplorerActualHTTP(t *testing.T, nodeFallback bool, countMode string, transferKinds ...bool) {
	strictCounts := countMode == "strict" || countMode == "block-strict"
	blockMode := strings.HasPrefix(countMode, "block-")
	typed := len(transferKinds) > 0 && transferKinds[0]
	indexertest.Require(t)
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
	coin, err := types.SignTx(types.NewTransaction(0, target, big.NewInt(7), 100000, big.NewInt(1), nil), types.LatestSignerForChainID(big.NewInt(1)), f.HistoryKey(1))
	if err != nil {
		t.Fatal(err)
	}
	listed := f.HistoryTransaction(t, 2, 1, target)
	hidden := f.HistoryTransaction(t, 3, 2, common.HexToAddress("0x987654"))
	txs := []*types.Transaction{coin, hidden, listed}
	if countMode == "large" || countMode == "block-large" {
		for n := 3; n < 220; n++ {
			txs = append(txs, f.HistoryTransaction(t, 1, uint64(n), target))
		}
	}
	ownerAddress := crypto.PubkeyToAddress(f.HistoryKey(1).PublicKey)
	transfer := &types.Log{Address: target, Topics: []common.Hash{crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)")), common.BytesToHash(ownerAddress.Bytes()), common.BytesToHash(target.Bytes())}, Data: common.LeftPadBytes([]byte{0xab}, 32)}
	ping := &types.Log{Address: target, Topics: []common.Hash{crypto.Keccak256Hash([]byte("Ping()"))}, Data: []byte{}}
	sourceEvents := []*types.Log{transfer, ping}
	if typed {
		sourceEvents = append(sourceEvents, transfer, transfer, transfer)
	}
	logsByTx := make([][]*types.Log, len(txs))
	logsByTx[0] = sourceEvents
	node := f.NewHistoryNode(t, txs, logsByTx)
	network := node.Network()
	var instant atomic.Int64
	instant.Store(f.Now)
	clock := func() time.Time { return time.Unix(instant.Load(), 0) }
	src := f.DefaultStateFixture(t)
	src.HistoryConsumer = true
	if strictCounts {
		src.ReadProfile = "strict"
	}
	contract := f.ReadContract(target.Hex())
	contract.ABI = json.RawMessage(`[{"anonymous":false,"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]},{"anonymous":false,"type":"event","name":"Ping","inputs":[]}]`)
	contract.ReadGrants[0].EventRules = policybundle.EventRules{Mode: "all", Rules: []policybundle.EventRule{}}
	src.Contracts[f.Org] = []policybundle.Contract{contract}
	if countMode == "no-logs" {
		for i := range src.Groups[f.Org] {
			methods := []string{}
			for _, method := range src.Groups[f.Org][i].AllowedMethods {
				if method != "eth_getLogs" {
					methods = append(methods, method)
				}
			}
			src.Groups[f.Org][i].AllowedMethods = methods
		}
	}
	if countMode == "block-no-tx" {
		for i := range src.Groups[f.Org] {
			methods := []string{}
			for _, method := range src.Groups[f.Org][i].AllowedMethods {
				if method != "eth_getTransactionByHash" {
					methods = append(methods, method)
				}
			}
			src.Groups[f.Org][i].AllowedMethods = methods
		}
	}
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
	scope := a.Scope{Network: key, Hash: listed.Hash(), Actor: f.Actor(f.AdminSubject), Organization: f.Org, State: state}
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
	stateRaw, _ := json.Marshal(rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}})
	statePolicy, err := rpcstatepolicy.Compile(stateRaw, rpcstatepolicy.Digest(sha256.Sum256(stateRaw)))
	if err != nil {
		t.Fatal(err)
	}
	stateClient, err := rpcexecution.NewStateClient(node.Transport(), rpcexecution.MetadataSource{Network: network, URL: node.Source("").URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	stateEngine, err := rpcengine.NewState(rpcengine.StateConfig{Snapshot: snapshot, Policy: statePolicy, Network: network, Default: stateClient, Clients: map[rpcengine.StateBindingKey]*rpcexecution.StateClient{{OrganizationID: f.Org}: stateClient, {OrganizationID: f.OtherOrg}: stateClient}, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	var fallbackNode *f.HistoryNode
	if nodeFallback {
		fallbackNode = node
	}
	index, indexOwner, binding := actualExplorerIndex(t, d.owner, d.ownerDSN, network, fallbackNode, countMode == "slow")
	if blockMode {
		if _, err = indexOwner.Exec(ctx, `UPDATE blocks SET transaction_count=999 WHERE number=1`); err != nil {
			t.Fatal(err)
		}
	}
	var selectedIndex explorerquery.Source = index
	failCountRecheck := &atomic.Bool{}
	if countMode == "slow" || countMode == "recheck" {
		selectedIndex = &optionalCountIndex{Reader: index, slow: countMode == "slow", fail: failCountRecheck}
	}
	if _, err = indexOwner.Exec(ctx, `UPDATE blocks SET hash=$1,gas_used=$2,transaction_count=$3 WHERE number=1`, strings.ToLower(node.Hash().Hex()), 21000*len(txs), len(txs)); err != nil {
		t.Fatal(err)
	}
	for i, tx := range txs {
		sender, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = indexOwner.Exec(ctx, `INSERT INTO transactions(hash,block_number,tx_index,from_address,to_address,value,gas_used,gas_price,status,input_data,nonce)VALUES($1,1,$2,$3,$4,$5,21000,1,1,$6,$7)`, strings.ToLower(tx.Hash().Hex()), i, strings.ToLower(sender.Hex()), strings.ToLower(tx.To().Hex()), tx.Value().String(), common.Bytes2Hex(tx.Data()), int64(tx.Nonce()))
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, event := range sourceEvents {
		topics := make([]any, 4)
		for j, topic := range event.Topics {
			topics[j] = strings.ToLower(topic.Hex())
		}
		_, err = indexOwner.Exec(ctx, `INSERT INTO logs(tx_hash,log_index,address,topic0,topic1,topic2,topic3,data,block_number,timestamp,removed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,false)`, strings.ToLower(coin.Hash().Hex()), i, strings.ToLower(target.Hex()), topics[0], topics[1], topics[2], topics[3], common.Bytes2Hex(event.Data), f.Now)
		if err != nil {
			t.Fatal("writer-shaped event row", err)
		}
	}

	seeds := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tokens(address,symbol,name,decimals,token_type,total_supply,holder_count,transfer_count,block_number)VALUES($1,'TOK','Visible token',18,'ERC20',1000,999,999,1)`, []any{strings.ToLower(target.Hex())}},
		{`INSERT INTO address_stats(address,tx_count,token_transfer_count,internal_tx_count)VALUES($1,999,999,999),($2,999,999,999),($3,999,999,999)`, []any{strings.ToLower(target.Hex()), strings.ToLower(ownerAddress.Hex()), "0x0000000000000000000000000000000000009999"}},
		{`INSERT INTO token_balances_current(token_address,address,balance,block_number)VALUES($1,$2,10,1),($1,$3,20,1)`, []any{strings.ToLower(target.Hex()), strings.ToLower(ownerAddress.Hex()), "0x0000000000000000000000000000000000009999"}},
		{`INSERT INTO token_transfers(tx_hash,log_index,token_address,from_address,to_address,value,block_number,timestamp)VALUES($1,0,$2,$3,$2,171,1,$4)`, []any{strings.ToLower(coin.Hash().Hex()), strings.ToLower(target.Hex()), strings.ToLower(ownerAddress.Hex()), f.Now}},
	}
	for _, seed := range seeds {
		if _, err = indexOwner.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatal("count source facts", err)
		}
	}
	if typed {
		for _, i := range []int{2, 3, 4} {
			_, err = indexOwner.Exec(ctx, `INSERT INTO token_transfers(tx_hash,log_index,token_address,from_address,to_address,value,block_number,timestamp,token_type,transfer_type) VALUES($1,$2,$3,$4,$3,171,1,$5,'ERC20','transfer')`, strings.ToLower(coin.Hash().Hex()), i, strings.ToLower(target.Hex()), strings.ToLower(ownerAddress.Hex()), f.Now)
			if err != nil {
				t.Fatal(err)
			}
		}
		// A non-owned transaction remains hidden, independently of a matching
		// source type. Its presence cannot create a visible transfer.
		_, err = indexOwner.Exec(ctx, `INSERT INTO token_transfers(tx_hash,log_index,token_address,from_address,to_address,value,block_number,timestamp,token_type,transfer_type) VALUES($1,5,$2,$3,$2,1,1,$4,'ERC721','transfer')`, strings.ToLower(hidden.Hash().Hex()), strings.ToLower(target.Hex()), strings.ToLower(hidden.To().Hex()), f.Now)
		if err != nil {
			t.Fatal(err)
		}
	}
	blockFailRead, blockFailRecheck := &atomic.Bool{}, &atomic.Bool{}
	if blockMode {
		selectedIndex = &optionalBlockCountIndex{Reader: index, failRead: blockFailRead, failRecheck: blockFailRecheck}
	}
	explorer, err := rpcengine.NewExplorer(rpcengine.ExplorerConfig{Snapshot: snapshot, History: history, State: stateEngine, Metadata: metadata, Index: selectedIndex, IndexExpected: binding, CursorKey: bytes.Repeat([]byte{13}, 32), PseudonymKey: bytes.Repeat([]byte{14}, 32)})
	if err != nil {
		t.Fatal("concrete Explorer constructor", err)
	}
	methods := append(history.OperationBinding().Methods, metadata.OperationBinding().Methods...)
	methods = append(methods, stateEngine.OperationBinding().Methods...)
	methods = append(methods, activitymethoddata.ExplorerLabels()...)
	entered, release := make(chan struct{}), make(chan struct{})
	var sealCount atomic.Int32
	var reorgAtSeal atomic.Bool
	var expireBlockAtSeal atomic.Bool
	recorder := rpcRecorder(t, activity, clock, func(uint64) error {
		if countMode == "expiry" || expireBlockAtSeal.Swap(false) {
			instant.Add(600)
		}
		if countMode == "recheck" {
			failCountRecheck.Store(true)
		}
		if reorgAtSeal.Swap(false) {
			node.Reorg(true)
		}
		if sealCount.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}, methods...)
	service, err := rpcactivity.New(rpcactivity.Config{Snapshot: snapshot, Clock: clock, History: history, State: stateEngine, Metadata: metadata, Explorer: explorer, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.ExplorerHandler(f.Org)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	type result struct {
		status int
		body   []byte
		err    error
	}
	get := func(path string) <-chan result {
		done := make(chan result, 1)
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), "GET", server.URL+path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set(rpcactivity.RequestReferenceHeader, "caller-supplied-is-not-trusted")
			response, err := server.Client().Do(req)
			if err != nil {
				done <- result{err: err}
				return
			}
			defer response.Body.Close()
			if response.StatusCode != 503 && !a.ValidUUID(response.Header.Get(rpcactivity.RequestReferenceHeader)) {
				t.Error("durable Explorer response lacks recorder reference")
			}
			raw, err := io.ReadAll(response.Body)
			done <- result{response.StatusCode, raw, err}
		}()
		return done
	}

	if countMode != "standard" {
		close(release)
	}

	if blockMode {
		decode := func(response result) wire.Block {
			t.Helper()
			var block wire.Block
			if response.status != 200 || json.Unmarshal(response.body, &block) != nil || block.Hash == "" {
				t.Fatal("block response", response.status, string(response.body))
			}
			return block
		}
		assertCount := func(block wire.Block, want string) {
			t.Helper()
			count := block.Counts["transactions"]
			if count.Status != "exact" || count.Value == nil || string(*count.Value) != want || block.TransactionCount == nil || string(*block.TransactionCount) != want || count.Range == nil || count.Range.FromBlock != block.Number || count.Range.ThroughBlock != block.Number || count.Range.HeadHash != block.Hash {
				t.Fatal("count/scalar/selected canonical range", block, count)
			}
		}
		first := decode(<-get("/api/v2/explorer/blocks/1"))
		if countMode == "block-no-tx" {
			if first.TransactionCount != nil || first.Counts["transactions"].Status != "unavailable" || first.Counts["transactions"].ObservedAt != nil || node.Calls()["eth_getTransactionByHash"] != 0 {
				t.Fatal("header permission granted transaction facts", first, node.Calls())
			}
			return
		}
		if countMode == "block-large" {
			count := first.Counts["transactions"]
			if count.Status != "at_least" || count.LowerBound == nil || first.TransactionCount != nil || count.Range == nil || count.Range.HeadHash != first.Hash {
				t.Fatal("large block fabricated exact total", first)
			}
			bound, ok := new(big.Int).SetString(string(*count.LowerBound), 10)
			if !ok || bound.Cmp(big.NewInt(25)) <= 0 {
				t.Fatal("block count did not qualify rows beyond the ordinary first page", first)
			}
			return
		}
		want := "2"
		if strictCounts {
			want = "1"
		}
		assertCount(first, want)
		assertCount(decode(<-get("/api/v2/explorer/blocks/hash/"+first.Hash)), want)
		head := node.AdvanceEmptyHead2()
		if _, err = indexOwner.Exec(ctx, `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count)VALUES(2,$1,$2,$3,0,30000000,999);UPDATE sync_status SET last_indexed_block=2`, pgx.QueryExecModeSimpleProtocol, strings.ToLower(head.Hash().Hex()), strings.ToLower(node.Hash().Hex()), head.Time); err != nil {
			t.Fatal(err)
		}
		assertCount(decode(<-get("/api/v2/explorer/blocks/2")), "0")
		grouped := <-get("/api/v2/explorer/blocks?limit=25")
		var page wire.Page[wire.Block]
		if grouped.status != 200 || json.Unmarshal(grouped.body, &page) != nil || len(page.Items) != 2 {
			t.Fatal("block group", grouped.status, string(grouped.body))
		}
		for _, block := range page.Items {
			if block.Number == "1" {
				assertCount(block, want)
			} else if block.Number == "2" {
				assertCount(block, "0")
			} else {
				t.Fatal("unexpected group target", block)
			}
		}
		blockFailRead.Store(true)
		failed := decode(<-get("/api/v2/explorer/blocks/1"))
		blockFailRead.Store(false)
		if failed.TransactionCount != nil || failed.Counts["transactions"].Status != "unavailable" {
			t.Fatal("source failure fabricated zero or broke header", failed)
		}
		blockFailRecheck.Store(true)
		failed = decode(<-get("/api/v2/explorer/blocks/1"))
		blockFailRecheck.Store(false)
		if failed.TransactionCount != nil || failed.Counts["transactions"].Status != "unavailable" {
			t.Fatal("final count failure released stale facts", failed)
		}
		reorgAtSeal.Store(true)
		reorg := <-get("/api/v2/explorer/blocks/1")
		node.Reorg(false)
		if reorg.status == 200 {
			t.Fatal("parent reorg released header/count", string(reorg.body))
		}
		expireBlockAtSeal.Store(true)
		expired := <-get("/api/v2/explorer/blocks/1")
		if expired.status == 200 {
			t.Fatal("parent expiry released header/count", string(expired.body))
		}
		return
	}
	if countMode != "standard" && countMode != "strict" {
		response := <-get("/api/v2/explorer/stats?limit=1")
		if countMode == "expiry" {
			if response.status == 200 || bytes.Contains(response.body, []byte("observedTransactions")) {
				t.Fatal("expired identity published counts", response.status, string(response.body))
			}
			return
		}
		var stats struct {
			ObservedTransactions string
			TotalTransactions    *string
			Counts               map[string]struct {
				Status                        string
				Value, LowerBound, ObservedAt *string
			}
		}
		if response.status != 200 || json.Unmarshal(response.body, &stats) != nil || stats.ObservedTransactions != "1" {
			t.Fatal("optional count broke ordinary page", response.status, string(response.body))
		}
		switch countMode {
		case "large":
			if stats.Counts["transactions"].Status != "at_least" || stats.Counts["transactions"].LowerBound == nil || stats.TotalTransactions != nil {
				t.Fatal("cutoff pretended exact or lost safe bound", string(response.body))
			}
		case "no-logs":
			if stats.Counts["tokens"].Status != "unavailable" || stats.Counts["tokens"].Value != nil || stats.Counts["tokens"].ObservedAt != nil {
				t.Fatal("parent tx gate granted log population", string(response.body))
			}
		case "slow", "recheck":
			for _, count := range stats.Counts {
				if count.Status != "unavailable" || count.Value != nil || count.LowerBound != nil || count.ObservedAt != nil {
					t.Fatal("failed count released stale numeric facts", string(response.body))
				}
			}
		}
		t.Logf("countsfixture:%s", response.body)
		return
	}
	if strictCounts {
		response := <-get("/api/v2/explorer/stats?limit=1")
		var value struct {
			Counts map[string]struct {
				Status string
				Value  *string
			}
		}
		if response.status != 200 || json.Unmarshal(response.body, &value) != nil || value.Counts["transactions"].Status != "exact" || value.Counts["transactions"].Value == nil || *value.Counts["transactions"].Value != "1" {
			t.Fatal("strict ordinary transaction population (listed row excluded)", response.status, string(response.body))
		}
		return
	}
	pending := get("/api/v2/explorer/transactions?limit=1")
	await(t, entered)
	select {
	case r := <-pending:
		t.Fatal("Explorer bytes before synced Append", r)
	default:
	}
	busy := <-get("/api/v2/explorer/chain-id")
	if busy.status != 503 {
		t.Fatal("REST escaped same N limiter", busy.status, string(busy.body))
	}
	close(release)
	first := <-pending
	if first.err != nil || first.status != 200 {
		t.Fatal("actual Explorer flow", first.err, first.status, string(first.body))
	}
	if typed {
		type transferPage struct {
			Items []struct {
				LogIndex          uint32
				TokenType, TxHash string
			}
			Page struct{ Next string }
		}
		read := func(path string) transferPage {
			t.Helper()
			r := <-get(path)
			var p transferPage
			if r.status != 200 || json.Unmarshal(r.body, &p) != nil {
				t.Fatalf("transfer request %s: %d %s", path, r.status, r.body)
			}
			return p
		}
		const path = "/api/v2/explorer/transfers?limit=1&type=ERC20"
		first := read(path)
		if len(first.Items) != 1 || first.Page.Next == "" {
			t.Fatalf("missing first typed page: %+v", first)
		}
		seen := map[uint32]bool{}
		p := first
		for n := 0; n < 10; n++ {
			for _, item := range p.Items {
				if item.TokenType != "ERC20" || item.TxHash != strings.ToLower(coin.Hash().Hex()) || seen[item.LogIndex] {
					t.Fatalf("wrong/hidden/repeated row: %+v", item)
				}
				seen[item.LogIndex] = true
			}
			if p.Page.Next == "" {
				break
			}
			p = read(path + "&cursor=" + url.QueryEscape(p.Page.Next))
		}
		if len(seen) != 4 {
			t.Fatalf("filtered matches beyond first page missing: %v", seen)
		}
		for _, changed := range []string{"", "&type=ERC721", "&type=ERC1155"} {
			r := <-get("/api/v2/explorer/transfers?limit=1" + changed + "&cursor=" + url.QueryEscape(first.Page.Next))
			if r.status == 200 {
				t.Fatal("changed filter accepted sealed cursor", string(r.body))
			}
		}
		hiddenOnly := read("/api/v2/explorer/transfers?type=ERC721&limit=1")
		if len(hiddenOnly.Items) != 0 {
			t.Fatal("type selection widened current rights", hiddenOnly)
		}
		// The legacy unfiltered digest fixture is pinned in rpcengine. The
		// unfiltered cursor retains its old shape and continues unchanged.
		unfiltered := read("/api/v2/explorer/transfers?limit=1")
		if unfiltered.Page.Next == "" {
			t.Fatal("unfiltered cursor missing")
		}
		// Replay a cursor through the pre-change AEAD writer contract. Its
		// exact old digest excludes the new optional tokenKind field.
		const legacyQuery = `{"Route":"/transfers","Query":{"Family":"transfers","Address":"","Hash":"","Token":"","Topic0":"","Search":"","Block":null,"From":null,"Through":null,"Upper":null,"After":null,"DatasetEpoch":"","RunFloor":null,"RawLimit":4},"Limit":1,"Category":"","TokenType":"","Interval":""}`
		legacyDigest := sha256.Sum256([]byte(legacyQuery))
		block, _ := aes.NewCipher(bytes.Repeat([]byte{13}, 32))
		legacyAEAD, _ := cipher.NewGCM(block)
		raw, e := base64.RawURLEncoding.DecodeString(unfiltered.Page.Next)
		if e != nil {
			t.Fatal(e)
		}
		plain, e := legacyAEAD.Open(nil, raw[:legacyAEAD.NonceSize()], raw[legacyAEAD.NonceSize():], legacyDigest[:])
		if e != nil {
			t.Fatal("unfiltered cursor no longer uses legacy binding", e)
		}
		nonce := bytes.Repeat([]byte{42}, legacyAEAD.NonceSize())
		legacyCursor := base64.RawURLEncoding.EncodeToString(legacyAEAD.Seal(nonce, nonce, plain, legacyDigest[:]))
		replay := read("/api/v2/explorer/transfers?limit=1&cursor=" + url.QueryEscape(legacyCursor))
		if len(replay.Items) != 1 {
			t.Fatal("old unfiltered writer cursor failed to continue", replay)
		}
		node.Reorg(true)
		rejected := <-get(path + "&cursor=" + url.QueryEscape(first.Page.Next))
		if rejected.status == 200 {
			t.Fatal("typed continuation survived reorg")
		}
		node.Reorg(false)
		tok = f.Token(t, snapshot, f.AdminSubject, "ReadOnly")
		rejected = <-get(path + "&cursor=" + url.QueryEscape(first.Page.Next))
		if rejected.status == 200 {
			t.Fatal("typed continuation survived actor/auth capture change")
		}
		return
	}
	var page struct {
		Items []struct {
			Hash  string
			Value *string
		}
		Page struct {
			Next        string
			HasMore     *bool
			ScanLimited bool
			EndedAt     string
		}
	}
	if json.Unmarshal(first.body, &page) != nil || len(page.Items) != 1 || page.Items[0].Hash != strings.ToLower(listed.Hash().Hex()) || page.Items[0].Value == nil || *page.Items[0].Value != "7" || page.Page.Next == "" {
		t.Fatal("lossless genuine listed row and continuation", string(first.body))
	}
	if page.Page.EndedAt != "ENDED_AT_UNSPECIFIED" {
		t.Fatal("continued visible page incorrectly reports a terminal raw-index boundary", page.Page.EndedAt)
	}
	next := <-get("/api/v2/explorer/transactions?limit=1&cursor=" + url.QueryEscape(page.Page.Next))
	if next.status != 200 || !bytes.Contains(next.body, []byte(strings.ToLower(txs[0].Hash().Hex()))) {
		t.Fatal("actual current wallet row next", next.status, string(next.body))
	}
	for _, search := range []struct{ query, kind, value string }{{strings.ToLower(node.Hash().Hex()), "block", "1"}, {strings.ToLower(listed.Hash().Hex()), "transaction", strings.ToLower(listed.Hash().Hex())}} {
		response := <-get("/api/v2/explorer/search/suggestions?q=" + url.QueryEscape(search.query))
		var suggestions struct {
			Items []struct{ Type, Value string }
		}
		if response.status != 200 || json.Unmarshal(response.body, &suggestions) != nil {
			t.Fatal("actual node-qualified search failed", response.status, string(response.body))
		}
		found := false
		for _, item := range suggestions.Items {
			if item.Type == search.kind && item.Value == search.value {
				found = true
			}
		}
		if !found {
			t.Fatal("actual node-qualified search omitted existing result", search.kind, string(response.body))
		}
	}
	filtered := <-get("/api/v2/explorer/transactions?category=coin_transfer&limit=10")
	if filtered.status != 200 || !bytes.Contains(filtered.body, []byte(strings.ToLower(coin.Hash().Hex()))) || bytes.Contains(filtered.body, []byte(strings.ToLower(listed.Hash().Hex()))) {
		t.Fatal("actual native coin filter omitted wallet row or included contract call", filtered.status, string(filtered.body))
	}
	coinPath := "/api/v2/explorer/transactions/" + strings.ToLower(coin.Hash().Hex())
	listedPath := "/api/v2/explorer/transactions/" + strings.ToLower(listed.Hash().Hex())
	logPath := coinPath + "/logs?limit=10"
	emptyInput := <-get(coinPath)
	nonemptyInput := <-get(listedPath)
	bareLogs := <-get(logPath)
	var events struct {
		Items []struct {
			LogIndex uint32
			Data     string
		}
	}
	if emptyInput.status != 200 || !bytes.Contains(emptyInput.body, []byte(`"inputData":"0x"`)) || nonemptyInput.status != 200 || !bytes.Contains(nonemptyInput.body, []byte(`"inputData":"0x01020304"`)) {
		t.Fatal("actual writer-shaped empty/nonempty transaction bytes", emptyInput.status, string(emptyInput.body), nonemptyInput.status, string(nonemptyInput.body))
	}
	if bareLogs.status != 200 || json.Unmarshal(bareLogs.body, &events) != nil || len(events.Items) != 2 {
		t.Fatal("actual writer-shaped matched event route", bareLogs.status, string(bareLogs.body))
	}
	for _, event := range events.Items {
		want := "0x" + common.Bytes2Hex(transfer.Data)
		if event.LogIndex == 1 {
			want = "0x"
		}
		if event.Data != want {
			t.Fatal("canonical qualified event value", event.LogIndex, event.Data, want)
		}
	}
	if _, err = indexOwner.Exec(ctx, `UPDATE transactions SET input_data='0x'||input_data; UPDATE logs SET data='0x'||data`); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path     string
		original result
	}{{coinPath, emptyInput}, {listedPath, nonemptyInput}, {logPath, bareLogs}} {
		got := <-get(test.path)
		if got.status != 200 || !bytes.Equal(got.body, test.original.body) {
			t.Fatal("equivalent node-prefix rows changed actual route value", test.path, got.status, string(got.body))
		}
	}
	if _, err = indexOwner.Exec(ctx, `UPDATE transactions SET input_data=substring(input_data from 3); UPDATE logs SET data=substring(data from 3)`); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		hash    string
		value   any
		restore string
	}{{strings.ToLower(coin.Hash().Hex()), "01", ""}, {strings.ToLower(listed.Hash().Hex()), "01020305", "01020304"}, {strings.ToLower(coin.Hash().Hex()), nil, ""}} {
		if _, err = indexOwner.Exec(ctx, `UPDATE transactions SET input_data=$1 WHERE hash=$2`, test.value, test.hash); err != nil {
			t.Fatal(err)
		}
		got := <-get("/api/v2/explorer/transactions/" + test.hash)
		if got.status == 200 {
			t.Fatal("mismatched/null indexed input accepted as actual node bytes", string(got.body))
		}
		if _, err = indexOwner.Exec(ctx, `UPDATE transactions SET input_data=$1 WHERE hash=$2`, test.restore, test.hash); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		index          int
		wrong, restore string
	}{{0, common.Bytes2Hex(common.LeftPadBytes([]byte{0xac}, 32)), common.Bytes2Hex(transfer.Data)}, {1, "00", ""}} {
		if _, err = indexOwner.Exec(ctx, `UPDATE logs SET data=$1 WHERE tx_hash=$2 AND log_index=$3`, test.wrong, strings.ToLower(coin.Hash().Hex()), test.index); err != nil {
			t.Fatal(err)
		}
		got := <-get(logPath)
		if got.status == 200 {
			t.Fatal("mismatched empty/nonempty indexed log accepted as actual receipt bytes", string(got.body))
		}
		if _, err = indexOwner.Exec(ctx, `UPDATE logs SET data=$1 WHERE tx_hash=$2 AND log_index=$3`, test.restore, strings.ToLower(coin.Hash().Hex()), test.index); err != nil {
			t.Fatal(err)
		}
	}
	// These are aggregates of the emitted page, never the raw cohort. The hidden
	// transaction is between the two visible transactions in descending order.
	var stats struct {
		ObservedTransactions, ObservedBlocks, ObservedParticipantAddresses string
		Page                                                               struct {
			Next     string
			HasMore  *bool
			Coverage string
		}
	}
	firstStats := <-get("/api/v2/explorer/stats?limit=1")
	if firstStats.status != 200 || json.Unmarshal(firstStats.body, &stats) != nil || stats.ObservedTransactions != "1" || stats.ObservedBlocks != "1" || stats.Page.Coverage != "OBSERVED_VISIBLE_PAGE" || stats.Page.Next == "" {
		t.Fatal("checked observed page stats", firstStats.status, string(firstStats.body))
	}

	var totals struct {
		Counts map[string]struct {
			Status string
			Value  *string
		}
		TotalTransactions *string
		TotalAddresses    *string
	}
	if json.Unmarshal(firstStats.body, &totals) != nil || totals.Counts["transactions"].Status != "exact" || totals.TotalTransactions == nil || *totals.TotalTransactions != "2" || totals.TotalAddresses == nil || *totals.TotalAddresses != "2" {
		t.Fatal("permitted totals differ from emitted ordinary populations", string(firstStats.body))
	}
	accountCounts := <-get("/api/v2/explorer/addresses/" + strings.ToLower(ownerAddress.Hex()) + "/stats")
	var account struct{ TxCount, TokenTransferCount, InternalTxCount *string }
	if accountCounts.status != 200 || json.Unmarshal(accountCounts.body, &account) != nil || account.TxCount == nil || *account.TxCount != "1" || account.TokenTransferCount == nil || *account.TokenTransferCount != "1" || account.InternalTxCount == nil || *account.InternalTxCount != "0" {
		t.Fatal("actual address counts copied raw or lost permitted rows", accountCounts.status, string(accountCounts.body))
	}
	tokenCounts := <-get("/api/v2/explorer/tokens/" + strings.ToLower(target.Hex()))
	var token struct{ HolderCount, TransferCount *string }
	if tokenCounts.status != 200 || json.Unmarshal(tokenCounts.body, &token) != nil || token.HolderCount == nil || *token.HolderCount != "1" || token.TransferCount == nil || *token.TransferCount != "1" {
		t.Fatal("actual token count population", tokenCounts.status, string(tokenCounts.body))
	}
	t.Logf("countsfixture:%s", firstStats.body)
	statsCursor := stats.Page.Next
	nextStats := <-get("/api/v2/explorer/stats?limit=1&cursor=" + url.QueryEscape(statsCursor))
	stats = struct {
		ObservedTransactions, ObservedBlocks, ObservedParticipantAddresses string
		Page                                                               struct {
			Next     string
			HasMore  *bool
			Coverage string
		}
	}{}
	if nextStats.status != 200 || json.Unmarshal(nextStats.body, &stats) != nil || stats.ObservedTransactions != "1" || stats.Page.Next != "" || stats.Page.HasMore == nil || *stats.Page.HasMore {
		t.Fatal("stats continuation skipped or counted hidden/lookahead row", nextStats.status, string(nextStats.body))
	}
	var chart struct {
		Items []struct{ Timestamp, Count string }
		Page  struct {
			Next     string
			Coverage string
		}
	}
	chartPage := <-get("/api/v2/explorer/stats/tx-history?interval=hour&limit=1")
	if chartPage.status != 200 || json.Unmarshal(chartPage.body, &chart) != nil || len(chart.Items) != 1 || chart.Items[0].Count != "1" || chart.Items[0].Timestamp != new(big.Int).SetInt64(f.Now-f.Now%3600).String() || chart.Page.Coverage != "OBSERVED_VISIBLE_PAGE" || chart.Page.Next == "" {
		t.Fatal("checked bucket without lookahead", chartPage.status, string(chartPage.body))
	}
	chartNext := <-get("/api/v2/explorer/stats/tx-history?interval=hour&limit=1&cursor=" + url.QueryEscape(chart.Page.Next))
	chart.Items = nil
	if chartNext.status != 200 || json.Unmarshal(chartNext.body, &chart) != nil || len(chart.Items) != 1 || chart.Items[0].Count != "1" {
		t.Fatal("bucket continues on next visible page", chartNext.status, string(chartNext.body))
	}
	wholeChart := <-get("/api/v2/explorer/stats/tx-history?interval=day&limit=10")
	if wholeChart.status != 200 || json.Unmarshal(wholeChart.body, &chart) != nil || len(chart.Items) != 1 || chart.Items[0].Count != "2" {
		t.Fatal("hidden row contributed to chart", wholeChart.status, string(wholeChart.body))
	}
	originalToken := tok
	tok = f.Token(t, snapshot, f.AdminSubject, "Local")
	emptyStats := <-get("/api/v2/explorer/stats?limit=10")
	if emptyStats.status != 200 || json.Unmarshal(emptyStats.body, &stats) != nil || stats.ObservedTransactions != "0" || stats.ObservedBlocks != "0" || stats.ObservedParticipantAddresses != "0" {
		t.Fatal("all-hidden cohort did not remain empty", emptyStats.status, string(emptyStats.body))
	}
	emptyChart := <-get("/api/v2/explorer/stats/tx-history?interval=day&limit=10")
	if emptyChart.status != 200 || json.Unmarshal(emptyChart.body, &chart) != nil || len(chart.Items) != 0 {
		t.Fatal("all-hidden chart exposed buckets", emptyChart.status, string(emptyChart.body))
	}
	tok = originalToken
	// The same cursor is bound to the original JWT and the captured upper.
	node.Reorg(true)
	changed := <-get("/api/v2/explorer/transactions?limit=1&cursor=" + url.QueryEscape(page.Page.Next))
	if changed.status == 200 {
		t.Fatal("reorg published protected indexed row", string(changed.body))
	}
	node.Reorg(false)
	if nodeFallback {
		head := node.AdvanceEmptyHead2()
		if _, err = indexOwner.Exec(ctx, `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count)VALUES(2,$1,$2,$3,0,30000000,0)`, strings.ToLower(head.Hash().Hex()), strings.ToLower(node.Hash().Hex()), head.Time); err != nil {
			t.Fatal(err)
		}
		if _, err = indexOwner.Exec(ctx, `UPDATE sync_status SET last_indexed_block=2;UPDATE prune_state SET pruned_through=1`); err != nil {
			t.Fatal(err)
		}
		// A physically retained index row below the watermark is unavailable on
		// the actual node. It must look identical to hidden and wholly absent rows.
		ghost := common.Hash{0x99}.Hex()
		absent := common.Hash{0x98}.Hex()
		if _, err = indexOwner.Exec(ctx, `INSERT INTO transactions(hash,block_number,tx_index,from_address,to_address,value,gas_used,gas_price,status,input_data)VALUES($1,1,9,$2,$3,7,21000,1,1,'')`, ghost, strings.ToLower(ownerAddress.Hex()), strings.ToLower(target.Hex())); err != nil {
			t.Fatal(err)
		}
		for _, point := range []struct{ path, hash string }{{"/api/v2/explorer/transactions/" + strings.ToLower(coin.Hash().Hex()), strings.ToLower(coin.Hash().Hex())}, {"/api/v2/explorer/blocks/1", strings.ToLower(node.Hash().Hex())}, {"/api/v2/explorer/blocks/hash/" + strings.ToLower(node.Hash().Hex()), strings.ToLower(node.Hash().Hex())}} {
			response := <-get(point.path)
			var object struct{ Hash, Source string }
			if response.status != 200 || json.Unmarshal(response.body, &object) != nil || object.Hash != point.hash || object.Source != "NODE" {
				t.Fatal("authorized actual NODE point failed", point.path, response.status, string(response.body))
			}
			if strings.Contains(point.path, "/blocks/") {
				block := wire.Block{}
				if json.Unmarshal(response.body, &block) != nil || block.TransactionCount != nil || block.Counts["transactions"].Status != "unavailable" {
					t.Fatal("NODE-only/pruned point pretended a known transaction total", string(response.body))
				}
			}

		}
		var opaque []byte
		for _, hash := range []string{strings.ToLower(hidden.Hash().Hex()), ghost, absent} {
			response := <-get("/api/v2/explorer/transactions/" + hash)
			if response.status != 200 || !bytes.Equal(bytes.TrimSpace(response.body), []byte("null")) || bytes.Contains(response.body, []byte("source")) {
				t.Fatal("hidden/pruned-unavailable/absent point leaked existence or provenance", response.status, string(response.body))
			}
			if opaque == nil {
				opaque = bytes.Clone(response.body)
			} else if !bytes.Equal(opaque, response.body) {
				t.Fatal("opaque point responses differ")
			}
		}
		callsBefore := node.Calls()["eth_getTransactionByHash"]
		historical := <-get("/api/v2/explorer/blocks/1/transactions")
		if historical.status != 410 || !bytes.Contains(historical.body, []byte("history_pruned")) || node.Calls()["eth_getTransactionByHash"] != callsBefore {
			t.Fatal("historical range fell back to node or hid pruning", historical.status, string(historical.body))
		}
		reorgAtSeal.Store(true)
		rejected := <-get("/api/v2/explorer/transactions/" + strings.ToLower(coin.Hash().Hex()))
		node.Reorg(false)
		if rejected.status == 200 || bytes.Contains(rejected.body, []byte(strings.ToLower(coin.Hash().Hex()))) || bytes.Contains(rejected.body, []byte(`"source":"NODE"`)) {
			t.Fatal("NODE point escaped final canonical reorg fence", rejected.status, string(rejected.body))
		}
	}
}

func actualExplorerIndex(t *testing.T, root *pgx.Conn, ownerDSN string, network networkidentity.Binding, node *f.HistoryNode, shortPurpose bool) (*explorerindex.Reader, *pgx.Conn, explorerquery.Binding) {
	t.Helper()
	ctx := t.Context()
	if _, err := root.Exec(ctx, `CREATE DATABASE explorer_http_test`); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(ownerDSN)
	u.Path = "/explorer_http_test"
	owner, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	indexertest.Schema(t, owner, network)
	if _, err = owner.Exec(ctx, `CREATE ROLE explorer_http_reader LOGIN NOINHERIT PASSWORD 'public-test-only'`); err != nil {
		t.Fatal(err)
	}
	indexertest.Grant(t, owner, "explorer_http_reader")
	if _, err = owner.Exec(ctx, `INSERT INTO blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count)VALUES(1,$1,$2,$3,42000,30000000,2)`, network.GenesisHash, network.GenesisHash, f.Now); err != nil {
		t.Fatal(err)
	}
	// Caller replaces the selected actual upper with its node hash before querying.
	u.User = url.UserPassword("explorer_http_reader", "public-test-only")
	if node != nil {
		reader, binding := indexertest.OpenWithNode(t, u.String(), network, node.Source("").URL, node.CertificatePEM())
		return reader, owner, binding
	}
	if shortPurpose {
		limits := explorerindex.DefaultLimits()
		limits.Timeout = 400 * time.Millisecond
		reader, binding := indexertest.OpenWithLimits(t, u.String(), network, limits)
		return reader, owner, binding
	}
	reader, binding := indexertest.Open(t, u.String(), network)
	return reader, owner, binding
}

// The ordinary reader remains real; these two failures exercise optional
// enhancement acquisition/final delivery without replacing source facts.
type optionalCountIndex struct {
	*explorerindex.Reader
	slow bool
	fail *atomic.Bool
}

func (s *optionalCountIndex) ReadCurrentCounts(ctx context.Context, q explorerquery.CurrentCountQuery) (*explorerquery.CurrentCountPass, error) {
	if s.slow {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.Reader.ReadCurrentCounts(ctx, q)
}
func (s *optionalCountIndex) RecheckCurrentCounts(ctx context.Context, p *explorerquery.CurrentCountPass) error {
	if s.fail.Load() {
		return explorerquery.ErrUnavailable
	}
	return s.Reader.RecheckCurrentCounts(ctx, p)
}

type optionalBlockCountIndex struct {
	*explorerindex.Reader
	failRead, failRecheck *atomic.Bool
}

func (s *optionalBlockCountIndex) ReadCohort(ctx context.Context, q explorerquery.Query) (*explorerquery.ReadPass, error) {
	if q.Family == explorerquery.Transactions && s.failRead.Load() {
		return nil, explorerquery.ErrUnavailable
	}
	return s.Reader.ReadCohort(ctx, q)
}
func (s *optionalBlockCountIndex) Recheck(ctx context.Context, p *explorerquery.ReadPass) error {
	if p.Query().Family == explorerquery.Transactions && s.failRecheck.Load() {
		return explorerquery.ErrUnavailable
	}
	return s.Reader.Recheck(ctx, p)
}
