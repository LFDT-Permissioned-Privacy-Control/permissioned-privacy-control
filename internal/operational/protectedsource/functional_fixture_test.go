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

type functionalEmitter struct {
	Address      common.Address
	Organization string
}
type functionalEventNodeOptions struct {
	Logs     [][]*types.Log
	Keys     map[int]*ecdsa.PrivateKey
	To       map[int]*common.Address
	Emitters []functionalEmitter
}

func ownedFunctionalEventNode(t *testing.T, options functionalEventNodeOptions) *functionalNode {
	return ownedFunctionalNodeOptions(t, max(1, len(options.Logs)), 1, options)
}

type functionalNode struct {
	config            NodeConfig
	network           networkidentity.Binding
	genesis, head     *types.Header
	tx                *types.Transaction
	signer            *ecdsa.PrivateKey
	eventOptions      functionalEventNodeOptions
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
	return ownedFunctionalNodeOptions(t, count, perBlock, functionalEventNodeOptions{})
}

// Only explicit nil-To options use this real initcode, returning one STOP byte.
// Ordinary call fixtures keep their original signed bytes and receipt fields.
func functionalCreationInitCode() []byte {
	return []byte{0x60, 1, 0x60, 12, 0x60, 0, 0x39, 0x60, 1, 0x60, 0, 0xf3, 0}
}
func ownedFunctionalNodeOptions(t *testing.T, count, perBlock int, options functionalEventNodeOptions) *functionalNode {
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
		group := make([]*types.Transaction, perBlock)
		ethReceipts := make(types.Receipts, perBlock)
		gasUsed := make([]uint64, perBlock)
		var totalLogs uint32
		for j := range group {
			parentIndex := i*perBlock + j
			signer := key
			if options.Keys[parentIndex] != nil {
				signer = options.Keys[parentIndex]
			}
			destination := &to
			if override, ok := options.To[parentIndex]; ok {
				destination = override
			}
			logs := []*types.Log{}
			if parentIndex < len(options.Logs) {
				for _, entry := range options.Logs[parentIndex] {
					copy := *entry
					copy.Topics = append([]common.Hash{}, entry.Topics...)
					copy.Data = append([]byte{}, entry.Data...)
					copy.TxIndex = uint(j)
					copy.Index = uint(totalLogs)
					copy.Removed = false
					logs = append(logs, &copy)
					totalLogs++
				}
			}
			if totalLogs > 20000 {
				t.Fatal("event fixture exceeds receipt log bound")
			}
			gasUsed[j] = 21000 + 1000*uint64(len(logs))
			input := []byte{}
			if destination == nil {
				input = functionalCreationInitCode()
				gasUsed[j] += 100000
			}
			header.GasUsed += gasUsed[j]
			tx, err := types.SignNewTx(signer, types.LatestSignerForChainID(big.NewInt(1)), &types.LegacyTx{Nonce: uint64(parentIndex), To: destination, Gas: gasUsed[j], GasPrice: big.NewInt(3), Value: big.NewInt(0), Data: input})
			if err != nil {
				t.Fatal(err)
			}
			group[j] = tx
			ethReceipts[j] = &types.Receipt{Type: 0, Status: 1, CumulativeGasUsed: header.GasUsed, Logs: logs}
			if destination == nil {
				ethReceipts[j].ContractAddress = crypto.CreateAddress(crypto.PubkeyToAddress(signer.PublicKey), tx.Nonce())
			}
			ethReceipts[j].Bloom = types.CreateBloom(ethReceipts[j])
			for k, value := range ethReceipts[j].Bloom {
				header.Bloom[k] |= value
			}
		}
		if header.GasUsed > header.GasLimit {
			t.Fatal("event fixture exceeds block gas")
		}
		header.TxHash = types.DeriveSha(types.Transactions(group), trie.NewStackTrie(nil))
		header.ReceiptHash = types.DeriveSha(ethReceipts, trie.NewStackTrie(nil))
		number := "0x" + strconv.FormatUint(uint64(i+1), 16)
		items, receipts := make([]any, perBlock), make([]any, perBlock)
		for j, tx := range group {
			position := "0x" + strconv.FormatUint(uint64(j), 16)
			txFrom, err := types.Sender(types.LatestSignerForChainID(big.NewInt(1)), tx)
			if err != nil {
				t.Fatal(err)
			}
			transaction := fixtureObject(t, tx)
			transaction["from"], transaction["blockHash"], transaction["blockNumber"], transaction["transactionIndex"] = txFrom.Hex(), header.Hash().Hex(), number, position
			items[j] = transaction
			logs := make([]any, 0, len(ethReceipts[j].Logs))
			for _, entry := range ethReceipts[j].Logs {
				topics := make([]string, len(entry.Topics))
				for k, topic := range entry.Topics {
					topics[k] = topic.Hex()
				}
				logs = append(logs, map[string]any{"address": entry.Address.Hex(), "topics": topics, "data": "0x" + common.Bytes2Hex(entry.Data), "blockNumber": number, "blockHash": header.Hash().Hex(), "transactionHash": tx.Hash().Hex(), "transactionIndex": position, "logIndex": "0x" + strconv.FormatUint(uint64(entry.Index), 16), "removed": false})
			}
			var destination, created any
			if tx.To() != nil {
				destination = tx.To().Hex()
			} else {
				created = ethReceipts[j].ContractAddress.Hex()
			}
			receipts[j] = map[string]any{"transactionHash": tx.Hash().Hex(), "blockHash": header.Hash().Hex(), "blockNumber": number, "transactionIndex": position, "from": txFrom.Hex(), "to": destination, "type": "0x0", "contractAddress": created, "status": "0x1", "gasUsed": "0x" + strconv.FormatUint(gasUsed[j], 16), "cumulativeGasUsed": "0x" + strconv.FormatUint(ethReceipts[j].CumulativeGasUsed, 16), "effectiveGasPrice": "0x3", "logsBloom": "0x" + common.Bytes2Hex(ethReceipts[j].Bloom[:]), "logs": logs}
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
	findTransaction := func(hash string) (*types.Transaction, map[string]any, map[string]any) {
		for i, group := range groups {
			for j, tx := range group {
				if tx.Hash().Hex() == hash {
					return tx, blocksByHash[blocks[i].Hash().Hex()]["transactions"].([]any)[j].(map[string]any), receiptsByHash[blocks[i].Hash().Hex()][j].(map[string]any)
				}
			}
		}
		return nil, nil, nil
	}
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
		case "eth_getBlockByHash", "eth_getBlockByNumber":
			var hash string
			_ = json.Unmarshal(q.Params[0], &hash)
			if q.Method == "eth_getBlockByNumber" {
				if number, err := strconv.ParseUint(strings.TrimPrefix(hash, "0x"), 16, 64); err == nil && headers[number] != nil {
					hash = headers[number].Hash().Hex()
				}
			}
			if block, ok := blocksByHash[hash]; ok {
				result = block
				var full bool
				if len(q.Params) > 1 && json.Unmarshal(q.Params[1], &full) == nil && !full {
					copy := map[string]any{}
					for k, v := range block {
						copy[k] = v
					}
					hashes := []any{}
					for _, tx := range block["transactions"].([]any) {
						hashes = append(hashes, tx.(map[string]any)["hash"])
					}
					copy["transactions"] = hashes
					result = copy
				}
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
		case "eth_getTransactionByHash", "eth_getTransactionReceipt", "debug_traceTransaction":
			var hash string
			_ = json.Unmarshal(q.Params[0], &hash)
			tx, transaction, receipt := findTransaction(hash)
			if tx == nil {
				break
			}
			switch q.Method {
			case "eth_getTransactionByHash":
				result = transaction
			case "eth_getTransactionReceipt":
				result = receipt
			case "debug_traceTransaction":
				from, _ := types.Sender(types.LatestSignerForChainID(big.NewInt(1)), tx)
				trace := map[string]any{"type": "CALL", "from": from.Hex(), "input": "0x" + common.Bytes2Hex(tx.Data()), "value": "0x" + tx.Value().Text(16), "gas": "0x" + strconv.FormatUint(tx.Gas(), 16), "gasUsed": receipt["gasUsed"], "output": "0x", "calls": []any{}}
				if tx.To() == nil {
					trace["type"], trace["to"], trace["output"] = "CREATE", crypto.CreateAddress(from, tx.Nonce()).Hex(), "0x00"
				} else {
					trace["to"] = tx.To().Hex()
				}
				result = map[string]any{"callTracer": trace, "prestateTracer": map[string]any{}}
			}
		case "eth_getCode":
			var address string
			_ = json.Unmarshal(q.Params[0], &address)
			result = "0x"
			for i, group := range groups {
				for _, tx := range group {
					if tx.To() == nil {
						from, _ := types.Sender(types.LatestSignerForChainID(big.NewInt(1)), tx)
						if !strings.EqualFold(address, crypto.CreateAddress(from, tx.Nonce()).Hex()) {
							continue
						}
						before := false
						if len(q.Params) > 1 {
							var tag string
							if json.Unmarshal(q.Params[1], &tag) == nil {
								if n, e := strconv.ParseUint(strings.TrimPrefix(tag, "0x"), 16, 64); e == nil {
									before = n < blocks[i].Number.Uint64()
								}
							} else {
								var selector struct {
									BlockHash string `json:"blockHash"`
								}
								if json.Unmarshal(q.Params[1], &selector) == nil {
									before = selector.BlockHash == genesis.Hash().Hex()
								}
							}
						}
						if !before {
							result = "0x00"
						}
					}
				}
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
	}, blocks: blocks, transactions: transactions, transactionGroups: groups, eventOptions: options, attempts: attempts.Load}
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
	statement := map[string]any{"kind": "prague-finite", "runtimeHash": h.Hash{9}.String(), "runtimeLength": 1, "initial": map[string]any{"kind": "org", "organizationId": f.Org}, "physical": map[string]any{"kind": "preexisting"}, "start": h.Cut{Number: 0, Hash: h.Hash(node.genesis.Hash()), Index: 0}, "end": h.Cut{Number: node.head.Number.Uint64(), Hash: h.Hash(node.head.Hash()), Index: uint32(len(node.transactionGroups[len(node.transactionGroups)-1]))}}
	statements := []any{}
	if node.tx.To() != nil {
		statement["address"] = strings.ToLower(node.tx.To().Hex())
		statements = append(statements, statement)
	}
	for _, emitter := range node.eventOptions.Emitters {
		item := map[string]any{}
		for key, value := range statement {
			item[key] = value
		}
		item["address"] = strings.ToLower(emitter.Address.Hex())
		item["initial"] = map[string]any{"kind": "org", "organizationId": emitter.Organization}
		statements = append(statements, item)
	}
	state := metadata.State
	if len(statements) > 0 {
		artifact, _ := json.Marshal(map[string]any{"apiVersion": h.ArtifactAPIVersion, "modelId": h.ModelID, "network": node.network, "era": era, "cohortId": uuid.NewString(), "statements": statements})
		path := filepath.Join(t.TempDir(), "namespace.json")
		if err = os.WriteFile(path, artifact, 0600); err != nil {
			t.Fatal(err)
		}
		imported, err := admissionsql.ImportNamespace(ctx, admissionDSN, binding, metadata.State, path, h.Digest(sha256.Sum256(artifact)), nil, true)
		if err != nil {
			t.Fatal("finite import", err)
		}
		state = imported.State
	}
	if err = admissionsql.FinalizeNamespaceRecovery(ctx, admissionDSN, binding, state, h.Digest{7}, true, true, 60); err != nil {
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
			txFrom, err := types.Sender(types.LatestSignerForChainID(big.NewInt(1)), tx)
			if err != nil {
				t.Fatal(err)
			}
			var to any
			if tx.To() != nil {
				to = strings.ToLower(tx.To().Hex())
			}
			functionalExec(t, indexOwner, `INSERT INTO public.transactions(hash,block_number,tx_index,from_address,to_address,value,gas_used,gas_price,status)VALUES($1,$2,$3,$4,$5,0,$6,3,1)`, tx.Hash().Hex(), header.Number.Uint64(), j, strings.ToLower(txFrom.Hex()), to, tx.Gas())
			if tx.To() == nil {
				functionalExec(t, indexOwner, `INSERT INTO public.contracts(address,bytecode,bytecode_hash,creator,creation_tx,block_number)VALUES($1,'0x00',$2,$3,$4,$5)`, strings.ToLower(crypto.CreateAddress(txFrom, tx.Nonce()).Hex()), crypto.Keccak256Hash([]byte{0}).Hex(), strings.ToLower(txFrom.Hex()), tx.Hash().Hex(), header.Number.Uint64())
			}
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
