package protectedsource

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	c "privacy-proxy/internal/creationfacts"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/disclosurewallet"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/indexertest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/rpcexecution"
)

type functionalDB struct {
	root *pgx.Conn
	url  *url.URL
}

func ownedFunctionalDB(t *testing.T) *functionalDB {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--pull=never", "--memory=384m", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=retained-public-test-only", "--env", "POSTGRES_DB=postgres", "--name", "ops-v2-retained-"+uuid.NewString()[:8], "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatal("owned PostgreSQL", err, string(raw))
	}
	id := strings.TrimSpace(string(raw))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "--force", id).Run()
	})
	raw, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("postgres://postgres:retained-public-test-only@" + strings.TrimSpace(string(raw)) + "/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	var owner *pgx.Conn
	for ctx.Err() == nil {
		owner, err = pgx.Connect(ctx, u.String())
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	return &functionalDB{owner, u}
}
func (db *functionalDB) database(t *testing.T, name string) (string, *pgx.Conn) {
	t.Helper()
	if _, err := db.root.Exec(t.Context(), "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	u := *db.url
	u.Path = "/" + name
	owner, err := pgx.Connect(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	return u.String(), owner
}
func functionalExec(t *testing.T, owner *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := owner.Exec(t.Context(), sql, args...); err != nil {
		t.Fatal("owned setup", err)
	}
}
func functionalRole(t *testing.T, owner *pgx.Conn, name string) {
	t.Helper()
	functionalExec(t, owner, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN NOINHERIT PASSWORD 'retained-public-test-only'")
}
func functionalDSN(dsn, role string) string {
	u, _ := url.Parse(dsn)
	u.User = url.UserPassword(role, "retained-public-test-only")
	return u.String()
}
func fixtureObject(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

type functionalNode struct {
	config            NodeConfig
	network           networkidentity.Binding
	genesis, head     *types.Header
	tx                *types.Transaction
	signer            *ecdsa.PrivateKey
	advanceHead       func(bool)
	blocks            []*types.Header
	transactions      []*types.Transaction
	transactionGroups [][]*types.Transaction
	attempts          func() int64
}

// This is a TLS protocol fixture, not a live-node qualification claim. Its
// signed transaction/header/receipt bytes cross the real CB1 acquisition.
func ownedFunctionalNode(t *testing.T) *functionalNode {
	t.Helper()
	return ownedFunctionalNodeCount(t, 1)
}

// Each transaction belongs to a distinct, chained canonical block. This keeps
// whole-block qualification and the physical request budget visible to tests.
func ownedFunctionalNodeCount(t *testing.T, count int) *functionalNode {
	t.Helper()
	return ownedFunctionalNodeShape(t, count, 1)
}

func ownedFunctionalNodeShape(t *testing.T, count, perBlock int) *functionalNode {
	t.Helper()
	if count < 1 || count > 128 || perBlock < 1 || perBlock > 100 || count*perBlock > 128 {
		t.Fatal("bounded functional block/transaction count required")
	}
	key, err := crypto.HexToECDSA(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	zero := uint64(0)
	withdrawals := types.EmptyWithdrawalsHash
	beacon := common.Hash{3}
	requests := types.EmptyRequestsHash
	genesis := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: uint64(f.Now - int64(count) - 1), BaseFee: big.NewInt(1), UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}, WithdrawalsHash: &withdrawals, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon, RequestsHash: &requests}
	from := crypto.PubkeyToAddress(key.PublicKey)
	headers := map[uint64]*types.Header{0: genesis}
	empty := fixtureObject(t, genesis)
	empty["transactions"], empty["uncles"], empty["withdrawals"] = []any{}, []any{}, []any{}
	blocksByHash := map[string]map[string]any{genesis.Hash().Hex(): empty}
	receiptsByHash := map[string][]any{genesis.Hash().Hex(): {}}
	blocks := make([]*types.Header, 0, count)
	transactions := make([]*types.Transaction, 0, count*perBlock)
	groups := make([][]*types.Transaction, 0, count)
	parent := genesis
	for i := 0; i < count; i++ {
		header := types.CopyHeader(genesis)
		header.Number, header.Time, header.ParentHash = big.NewInt(int64(i+1)), parent.Time+1, parent.Hash()
		header.GasUsed = 21000 * uint64(perBlock)
		group := make([]*types.Transaction, perBlock)
		ethReceipts := make(types.Receipts, perBlock)
		for j := range group {
			tx, err := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(1)), &types.LegacyTx{Nonce: uint64(i*perBlock + j), To: &to, Gas: 21000, GasPrice: big.NewInt(3), Value: big.NewInt(0), Data: []byte{}})
			if err != nil {
				t.Fatal(err)
			}
			group[j] = tx
			ethReceipts[j] = &types.Receipt{Type: 0, Status: 1, CumulativeGasUsed: 21000 * uint64(j+1), Logs: []*types.Log{}}
		}
		header.TxHash = types.DeriveSha(types.Transactions(group), trie.NewStackTrie(nil))
		header.ReceiptHash = types.DeriveSha(ethReceipts, trie.NewStackTrie(nil))
		number := "0x" + strconv.FormatUint(uint64(i+1), 16)
		items, receipts := make([]any, perBlock), make([]any, perBlock)
		for j, tx := range group {
			position := "0x" + strconv.FormatUint(uint64(j), 16)
			transaction := fixtureObject(t, tx)
			transaction["from"], transaction["blockHash"], transaction["blockNumber"], transaction["transactionIndex"] = from.Hex(), header.Hash().Hex(), number, position
			items[j] = transaction
			receipts[j] = map[string]any{"transactionHash": tx.Hash().Hex(), "blockHash": header.Hash().Hex(), "blockNumber": number, "transactionIndex": position, "from": from.Hex(), "to": to.Hex(), "type": "0x0", "contractAddress": nil, "status": "0x1", "gasUsed": "0x5208", "cumulativeGasUsed": "0x" + strconv.FormatUint(21000*uint64(j+1), 16), "effectiveGasPrice": "0x3", "logsBloom": "0x" + strings.Repeat("00", 256), "logs": []any{}}
		}
		block := fixtureObject(t, header)
		block["transactions"], block["uncles"], block["withdrawals"] = items, []any{}, []any{}
		headers[uint64(i+1)], blocksByHash[header.Hash().Hex()], receiptsByHash[header.Hash().Hex()] = header, block, receipts
		blocks, transactions, groups = append(blocks, header), append(transactions, group...), append(groups, group)
		parent = header
	}
	head := blocks[len(blocks)-1]
	latest := head
	var latestMu sync.RWMutex
	var attempts atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		var q struct {
			JSONRPC string            `json:"jsonrpc"`
			ID      uint64            `json:"id"`
			Method  string            `json:"method"`
			Params  []json.RawMessage `json:"params"`
		}
		if request.Header.Get("Idempotency-Key") != "retained-functional" || json.NewDecoder(request.Body).Decode(&q) != nil {
			t.Error("wrong selected node request")
			w.WriteHeader(400)
			return
		}
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_syncing":
			result = false
		case "eth_getHeaderByNumber":
			var selector string
			_ = json.Unmarshal(q.Params[0], &selector)
			if selector == "latest" {
				latestMu.RLock()
				result = latest
				latestMu.RUnlock()
			} else if number, err := strconv.ParseUint(strings.TrimPrefix(selector, "0x"), 16, 64); err == nil && strings.HasPrefix(selector, "0x") {
				latestMu.RLock()
				switch {
				case number > latest.Number.Uint64():
					// A well-formed future height is an ordinary missing header.
					result = nil
				case number == latest.Number.Uint64():
					result = latest
				case headers[number] != nil:
					result = headers[number]
				default:
					t.Error("missing canonical fixture header", selector)
				}
				latestMu.RUnlock()
			} else {
				t.Error("unknown header number", selector)
			}
		case "eth_getBlockByHash":
			var hash string
			_ = json.Unmarshal(q.Params[0], &hash)
			if block, ok := blocksByHash[hash]; ok {
				result = block
			} else {
				t.Error("unknown block hash")
			}
		case "eth_getBlockReceipts":
			var hash string
			_ = json.Unmarshal(q.Params[0], &hash)
			if receipts, ok := receiptsByHash[hash]; ok {
				result = receipts
			} else {
				t.Error("unknown receipts block hash")
			}
		default:
			t.Error("unexpected node call", q.Method)
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	network := networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: genesis.Hash().Hex(), DeploymentID: "retained-functional"}
	net, _ := network.Key()
	source := c.Source{Network: c.Network{Key: c.Digest(net), Environment: network.Environment, ChainID: network.ChainID, Genesis: genesis.Hash(), Deployment: network.DeploymentID}, Organization: f.Org, URL: server.URL, CredentialRef: "retained", CredentialHeader: "Idempotency-Key", Profile: rpcexecution.IncludedProfileID, PragueStart: 0, PragueEnd: uint64(f.Now + 1000)}
	return &functionalNode{config: NodeConfig{Source: source, Credential: rpcexecution.Credential{Header: "Idempotency-Key", Value: "retained-functional"}, Transport: server.Client().Transport}, network: network, genesis: genesis, head: head, tx: transactions[0], signer: key, advanceHead: func(advance bool) {
		latestMu.Lock()
		defer latestMu.Unlock()
		latest = head
		if advance {
			latest = types.CopyHeader(head)
			latest.Number = new(big.Int).Add(head.Number, big.NewInt(1))
			latest.ParentHash = head.Hash()
			latest.Time++
		}
	}, blocks: blocks, transactions: transactions, transactionGroups: groups, attempts: attempts.Load}
}

type functionalControl struct {
	wallet           *f.WalletFixture
	admission, index *pgx.Conn
}

func actualFunctionalConfig(t *testing.T, node *functionalNode, controls ...func(functionalControl)) Config {
	indexertest.Require(t)
	t.Helper()
	ctx := t.Context()
	db := ownedFunctionalDB(t)
	clock := func() time.Time { return time.Unix(f.Now, 0).UTC() }
	fixture := f.DefaultStateFixture(t)
	fixture.DeliveryConsumer = true
	rule := f.DefaultRule()
	rule.Resources = []p.Resource{p.ActivityLogs, p.ActivitySummary, p.AddressHistory, p.ComplianceReport, p.SanctionsReport, p.Transactions}
	rule.MaxLevel = p.Full
	fixture.DisclosureRules = []p.RuleSource{rule}
	snapshot := f.StateSnapshot(t, fixture)
	walletDSN, _ := db.database(t, "wallet")
	wallet := f.ActualWalletFixture(t, ctx, walletDSN, snapshot, node.network, clock)
	wallet.Link(t, ctx, f.Token(t, snapshot, f.Subject, "Auditor"), node.signer)
	u, _ := url.Parse(walletDSN)
	u.User = url.UserPassword("state_wallet_reader", "state-wallet-test-only")
	walletReader, err := walletsql.OpenReader(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(walletReader.Close)
	admissionDSN, admissionOwner := db.database(t, "admission")
	for _, role := range []string{"ad_app", "ad_reader", "ad_retention", "ad_observer", "ad_facts", "ad_namespace"} {
		functionalRole(t, admissionOwner, role)
	}
	if err = admissionsql.MigrateCreationObserver(ctx, admissionDSN, "ad_app", "ad_reader", "ad_retention", "ad_observer", "ad_facts"); err != nil {
		t.Fatal("admission migrate", err)
	}
	generation := uuid.NewString()
	binding := a.NetworkBinding(node.network)
	if err = admissionsql.BootstrapEmpty(ctx, admissionDSN, binding, generation); err != nil {
		t.Fatal(err)
	}
	if err = admissionsql.MigrateNamespace(ctx, admissionDSN, "ad_namespace", true); err != nil {
		t.Fatal(err)
	}
	era := h.ModelEra{EntryNumber: 0, EntryHash: h.Hash(node.genesis.Hash()), EntryTimestamp: node.genesis.Time, EndTimestampExclusive: uint64(f.Now + 1000)}
	if err = admissionsql.BootstrapNamespace(ctx, admissionDSN, binding, generation, era, h.DefaultCapacityLimits(), true, true); err != nil {
		t.Fatal(err)
	}
	metadata, err := admissionsql.ReadNamespaceOwnerMetadata(ctx, admissionDSN, binding)
	if err != nil {
		t.Fatal(err)
	}
	statement := map[string]any{"kind": "prague-finite", "address": strings.ToLower(node.tx.To().Hex()), "runtimeHash": h.Hash{9}.String(), "runtimeLength": 1, "initial": map[string]any{"kind": "org", "organizationId": f.Org}, "physical": map[string]any{"kind": "preexisting"}, "start": h.Cut{Number: 0, Hash: h.Hash(node.genesis.Hash()), Index: 0}, "end": h.Cut{Number: node.head.Number.Uint64(), Hash: h.Hash(node.head.Hash()), Index: uint32(len(node.transactionGroups[len(node.transactionGroups)-1]))}}
	artifact, _ := json.Marshal(map[string]any{"apiVersion": h.ArtifactAPIVersion, "modelId": h.ModelID, "network": node.network, "era": era, "cohortId": uuid.NewString(), "statements": []any{statement}})
	path := filepath.Join(t.TempDir(), "namespace.json")
	if err = os.WriteFile(path, artifact, 0600); err != nil {
		t.Fatal(err)
	}
	imported, err := admissionsql.ImportNamespace(ctx, admissionDSN, binding, metadata.State, path, h.Digest(sha256.Sum256(artifact)), nil, true)
	if err != nil {
		t.Fatal("finite import", err)
	}
	if err = admissionsql.FinalizeNamespaceRecovery(ctx, admissionDSN, binding, imported.State, h.Digest{7}, true, true, 60); err != nil {
		t.Fatal(err)
	}
	namespace, err := admissionsql.OpenNamespaceReader(ctx, functionalDSN(admissionDSN, "ad_namespace"), binding, generation, era)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(namespace.Close)
	finance, err := admissionsql.OpenReader(ctx, functionalDSN(admissionDSN, "ad_reader"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(finance.Close)
	indexDSN, indexOwner := db.database(t, "indexer")
	indexertest.Schema(t, indexOwner, node.network)
	functionalRole(t, indexOwner, "retained_index_reader")
	indexertest.Grant(t, indexOwner, "retained_index_reader")
	functionalExec(t, indexOwner, `INSERT INTO public.blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count)VALUES(0,$1,$2,$3,$4,$5,0)`, node.genesis.Hash().Hex(), node.genesis.ParentHash.Hex(), node.genesis.Time, node.genesis.GasUsed, node.genesis.GasLimit)
	for i, header := range node.blocks {
		group := node.transactionGroups[i]
		functionalExec(t, indexOwner, `INSERT INTO public.blocks(number,hash,parent_hash,timestamp,gas_used,gas_limit,transaction_count)VALUES($1,$2,$3,$4,$5,$6,$7)`, header.Number.Uint64(), header.Hash().Hex(), header.ParentHash.Hex(), header.Time, header.GasUsed, header.GasLimit, len(group))
		for j, tx := range group {
			functionalExec(t, indexOwner, `INSERT INTO public.transactions(hash,block_number,tx_index,from_address,to_address,value,gas_used,gas_price,status)VALUES($1,$2,$3,$4,$5,0,21000,3,1)`, tx.Hash().Hex(), header.Number.Uint64(), j, strings.ToLower(crypto.PubkeyToAddress(node.signer.PublicKey).Hex()), strings.ToLower(tx.To().Hex()))
		}
	}
	readerDSN := functionalDSN(indexDSN, "retained_index_reader")
	index, _ := indexertest.Open(t, readerDSN, node.network)
	activityDSN, activityOwner := db.database(t, "activity")
	for _, role := range []string{"retained_activity_writer", "retained_activity_reader", "retained_activity_retention"} {
		functionalRole(t, activityOwner, role)
	}
	paths, err := filepath.Glob("../../db/migrations_audit/00[1-4]_*.sql")
	if err != nil || len(paths) != 4 {
		t.Fatal("audit baseline", err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		functionalExec(t, activityOwner, "BEGIN;"+string(raw)+";COMMIT")
	}
	roles := activitysql.RoleNames{Writer: "retained_activity_writer", Reader: "retained_activity_reader", Retention: "retained_activity_retention"}
	if err = activitysql.Migrate(ctx, activityDSN, roles.Writer, roles.Reader, roles.Retention, true); err != nil {
		t.Fatal(err)
	}
	registration := activitysql.Registration{Network: node.network, SourceID: uuid.NewString(), Configuration: [32]byte{1}, Limits: activitysql.DefaultStorageLimits(), Roles: roles}
	if err = activitysql.Initialize(ctx, activityDSN, registration, true); err != nil {
		t.Fatal(err)
	}
	network, _ := node.network.Key()
	status, err := activitysql.Status(ctx, activityDSN, network, registration.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	activity, err := activitysql.OpenReader(ctx, functionalDSN(activityDSN, roles.Reader), activitysql.Scope{NetworkKey: network, SourceID: registration.SourceID, ExpectedGeneration: status.Metadata.Generation})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(activity.Close)
	for _, receive := range controls {
		receive(functionalControl{wallet, admissionOwner, indexOwner})
	}
	return Config{Snapshot: snapshot, Network: node.network, Index: index, ExpectedIndex: index.Metadata(), Namespace: namespace, Nodes: map[string]NodeConfig{f.Org: node.config}, Wallet: disclosurewallet.Config{Store: walletReader, Binding: wallet.Binding, ExpectedState: wallet.State, Clock: clock}, Finance: admissionsql.FinanceReaderConfig{Store: finance, Network: binding, ExpectedState: a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}, Clock: clock}, Activity: activity, Clock: clock, RenderKeys: d.Keys{Active: d.Key{ID: "render", Bytes: []byte(strings.Repeat("!", 32))}}}
}
