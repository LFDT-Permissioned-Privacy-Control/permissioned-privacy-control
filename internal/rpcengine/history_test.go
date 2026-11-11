package rpcengine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpchistorypolicy"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

const historyABI = `[{"type":"event","name":"Seen","inputs":[{"name":"who","type":"address","indexed":true},{"name":"other","type":"address","indexed":false}]}]`

type historyWalletFacts struct {
	facts []walletops.OwnershipFact
	loads int
	after func()
}

func (s *historyWalletFacts) WithActorTransaction(context.Context, walletops.Namespace, walletops.ExpectedState, string, func(walletops.ActorTx) error) error {
	return walletops.ErrUnavailable
}
func (s *historyWalletFacts) ResolveActiveActors(context.Context, walletops.Namespace, walletops.ExpectedState, common.Address, int) ([]string, error) {
	return nil, walletops.ErrUnavailable
}
func (s *historyWalletFacts) LoadActive(context.Context, walletops.Namespace, walletops.ExpectedState, string, int) ([]walletops.OwnershipFact, error) {
	s.loads++
	if s.after != nil {
		s.after()
	}
	return append([]walletops.OwnershipFact{}, s.facts...), nil
}

type historyShares struct {
	meta        historyfacts.ShareMetadata
	rows        []a.Share
	reads       int
	lastLimit   int
	widenLimit  bool
	unavailable bool
}

func (s *historyShares) Metadata() historyfacts.ShareMetadata { return s.meta }
func (s *historyShares) Read(ctx context.Context, q historyfacts.ShareQuery) (*historyfacts.SharePass, error) {
	s.reads++
	s.lastLimit = q.ByteLimit()
	if s.unavailable {
		return nil, historyfacts.ErrUnavailable
	}
	fence, err := q.OperationFence(ctx)
	if err != nil {
		return nil, err
	}
	rows := []a.Share{}
	for _, row := range s.rows {
		for _, hash := range q.Hashes {
			if row.Hash == hash {
				rows = append(rows, row)
			}
		}
	}
	if s.widenLimit {
		q = historyfacts.ShareQuery{Hashes: q.Hashes}
	}
	return historyfacts.NewSharePass(s.meta.Identity, s.meta.Binding, q, rows, fence)
}
func (s *historyShares) Recheck(ctx context.Context, p *historyfacts.SharePass) error {
	next, err := s.Read(ctx, p.Query())
	if err != nil || p.ValidateFor(s.meta.Identity, s.meta.Binding) != nil || !p.SamePositives(next) {
		return historyfacts.ErrUnavailable
	}
	return nil
}

type historyEngineFixture struct {
	config              rpcengine.HistoryConfig
	node                *f.HistoryNode
	clock               atomic.Int64
	wallets             *historyWalletFacts
	shares              *historyShares
	own, hidden, target common.Address
	txs                 []*types.Transaction
}

func newHistoryEngineFixture(t *testing.T, strict, unlock bool, abiRaw string, modify ...func(*f.StateFixture)) *historyEngineFixture {
	t.Helper()
	x := &historyEngineFixture{own: crypto.PubkeyToAddress(f.HistoryKey(1).PublicKey), hidden: crypto.PubkeyToAddress(f.HistoryKey(3).PublicKey), target: common.HexToAddress("0x123456")}
	x.clock.Store(f.Now)
	x.txs = []*types.Transaction{f.HistoryTransaction(t, 1, 0, x.target), f.HistoryTransaction(t, 2, 1, x.target)}
	topic := crypto.Keccak256Hash([]byte("Seen(address,address)"))
	log := func() *types.Log {
		return &types.Log{Address: x.target, Topics: []common.Hash{topic, common.BytesToHash(x.own.Bytes())}, Data: common.LeftPadBytes(x.hidden.Bytes(), 32)}
	}
	x.node = f.NewHistoryNode(t, x.txs, [][]*types.Log{{log()}, {log()}})
	src := f.DefaultStateFixture(t)
	src.HistoryConsumer = true
	if strict {
		src.ReadProfile = "strict"
	}
	contract := f.ReadContract(x.target.Hex())
	contract.ABI = json.RawMessage(abiRaw)
	contract.AllowVisibleToUnlock = unlock
	contract.ReadGrants[0].EventRules.Mode = "all"
	src.Contracts[f.Org] = []policybundle.Contract{contract}
	for _, apply := range modify {
		apply(&src)
	}
	snapshot := f.StateSnapshot(t, src)
	network := x.node.Network()
	clock := func() time.Time { return time.Unix(x.clock.Load(), 0) }
	binding := walletops.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.GenesisHash, DeploymentID: network.DeploymentID}
	state := walletops.ExpectedState{Generation: "11111111-1111-1111-1111-111111111111"}
	ns, _ := binding.Namespace()
	x.wallets = &historyWalletFacts{facts: []walletops.OwnershipFact{{Namespace: ns, Actor: f.Actor(f.Subject), Address: x.own, ProofVersion: 2, VerifiedAt: time.Unix(f.Now, 0)}}}
	resolver, err := walletadapter.New(x.wallets, ns, state, clock)
	if err != nil {
		t.Fatal(err)
	}
	shareBinding := historyfacts.ShareBinding{Network: network, State: a.ExpectedState{Generation: "22222222-2222-2222-2222-222222222222"}, SchemaProfile: historyfacts.ShareSchemaProfile}
	x.shares = &historyShares{meta: historyfacts.ShareMetadata{Binding: shareBinding, Mode: "reader", Identity: historyfacts.NewReaderIdentity()}}
	policyRaw, _ := json.Marshal(rpchistorypolicy.Source{APIVersion: rpchistorypolicy.APIVersion, Kind: rpchistorypolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{"eth_getBlockByNumber"}})
	definition, err := rpchistorypolicy.Compile(policyRaw, rpchistorypolicy.Digest(sha256.Sum256(policyRaw)))
	if err != nil {
		t.Fatal(err)
	}
	limits := rpcexecution.DefaultHistoryReadLimits()
	client := func(org string) *rpcexecution.HistoryReadClient {
		c, err := rpcexecution.NewHistoryReadClient(x.node.Transport(), x.node.Source(org), rpcexecution.Credential{}, limits)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	clients := map[rpcengine.HistoryBindingKey]*rpcexecution.HistoryReadClient{}
	for _, org := range snapshot.Organizations() {
		for _, id := range snapshot.GroupIDs(org.ID) {
			g, _ := snapshot.Group(org.ID, id)
			for _, name := range g.AllowedMethods {
				m, _ := snapshot.Method(name)
				if _, ok := rpcexecution.HistoryMethodNamed(m.Canonical); ok {
					clients[rpcengine.HistoryBindingKey{OrganizationID: org.ID}] = client(org.ID)
					break
				}
			}
		}
	}
	x.config = rpcengine.HistoryConfig{Snapshot: snapshot, Policy: definition, Network: network, Default: client(""), Clients: clients, Wallets: resolver, WalletBinding: binding, WalletState: state, Shares: x.shares, ShareExpected: shareBinding, QueryLimits: limits, Clock: clock}
	if strict {
		x.config.Shares = nil
		x.config.ShareExpected = historyfacts.ShareBinding{}
	}
	return x
}
func (x *historyEngineFixture) engine(t *testing.T) *rpcengine.HistoryEngine {
	t.Helper()
	e, err := rpcengine.NewHistory(x.config)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func historyResponse(t *testing.T, e *rpcengine.HistoryEngine, token, org, method, params, id string) map[string]json.RawMessage {
	t.Helper()
	auth := []string{}
	if token != "" {
		auth = []string{"Bearer " + token}
	}
	raw := []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"` + method + `","params":` + params + `}`)
	r := e.QueryObserved(t.Context(), rpcengine.MetadataAuthorization(auth), org, raw)
	if r.PreflightFor(e) != nil {
		t.Fatal("result preflight")
	}
	if err := r.RequireDeliverable(t.Context(), e); err != nil {
		t.Fatal("delivery", err)
	}
	body, err := r.MarshalResponseFor(e)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if json.Unmarshal(body, &out) != nil {
		t.Fatal("response", string(body))
	}
	if string(out["id"]) != id {
		t.Fatal("original raw ID changed", string(out["id"]), id)
	}
	return out
}
func historyListed(t *testing.T, x *historyEngineFixture, hash common.Hash) {
	t.Helper()
	recipients, d, err := a.NormalizeRecipients([]string{f.Actor(f.Subject)})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := x.config.Network.Key()
	x.shares.rows = []a.Share{{Network: a.Digest(key), Hash: hash, Actor: f.Actor(f.AdminSubject), Organization: f.Org, Recipients: recipients, RecipientDigest: d, DeclaredAt: time.Unix(f.Now, 0), Witness: a.Witness{AnchorHash: common.Hash{1}, ManifestDigest: a.Digest{2}, WalletVersion: a.Digest{3}, WalletEvidenceAt: time.Unix(f.Now, 0)}}}
}

func TestHistoryEngineAllTenCurrentRPCSurfacesAndOriginalIDs(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "strict"}[strict], func(t *testing.T) {
			x := newHistoryEngineFixture(t, strict, false, historyABI)
			e := x.engine(t)
			token := f.Token(t, x.config.Snapshot, f.Subject, "Auditor")
			hash := x.node.Hash().Hex()
			params := []struct{ method, params string }{{"eth_getTransactionByHash", `["` + x.txs[0].Hash().Hex() + `"]`}, {"eth_getTransactionReceipt", `["` + x.txs[0].Hash().Hex() + `"]`}, {"eth_getBlockByHash", `["` + hash + `",true]`}, {"eth_getBlockByNumber", `["latest",false]`}, {"eth_getBlockTransactionCountByHash", `["` + hash + `"]`}, {"eth_getBlockTransactionCountByNumber", `["0x1"]`}, {"eth_getTransactionByBlockHashAndIndex", `["` + hash + `","0x0"]`}, {"eth_getTransactionByBlockNumberAndIndex", `["0x1","0x0"]`}, {"eth_getLogs", `[{"fromBlock":"0x1","toBlock":"0x1"}]`}, {"eth_getBlockReceipts", `["0x1"]`}}
			for i, tc := range params {
				id := `9007199254740993123456789`
				if i%2 == 1 {
					id = `"id-\u0031"`
				}
				out := historyResponse(t, e, token, f.Org, tc.method, tc.params, id)
				if out["error"] != nil || string(out["result"]) == "null" {
					t.Fatal(tc.method, string(out["error"]), string(out["result"]))
				}
				if strings.Contains(tc.method, "Count") && string(out["result"]) != `"0x1"` {
					t.Fatal("count includes hidden tx", string(out["result"]))
				}
				if tc.method == "eth_getBlockByHash" || tc.method == "eth_getBlockByNumber" {
					var block map[string]json.RawMessage
					_ = json.Unmarshal(out["result"], &block)
					var txs []json.RawMessage
					_ = json.Unmarshal(block["transactions"], &txs)
					if len(txs) != 1 || string(block["gasUsed"]) != `"0x0"` || bytes.Contains(block["logsBloom"], []byte("1")) {
						t.Fatal("block population/volume leak")
					}
				}
			}
			// Receipt-only log entitlement does not admit a transaction object; strict
			// keeps participant-only receipt envelopes even for an indexed-self log.
			out := historyResponse(t, e, token, f.Org, "eth_getTransactionByHash", `["`+x.txs[1].Hash().Hex()+`"]`, `1`)
			if string(out["result"]) != "null" {
				t.Fatal("event entitlement admitted transaction")
			}
			out = historyResponse(t, e, token, f.Org, "eth_getTransactionReceipt", `["`+x.txs[1].Hash().Hex()+`"]`, `1`)
			if (string(out["result"]) == "null") != strict {
				t.Fatal("receipt surface drift", string(out["result"]))
			}
			if strict && x.shares.reads != 0 {
				t.Fatal("strict touched unused shares")
			}
		})
	}
}
func TestHistoryEngineVisibleToAndMatchedLayoutBeforeEveryBypass(t *testing.T) {
	for _, strict := range []bool{false, true} {
		x := newHistoryEngineFixture(t, strict, true, historyABI)
		historyListed(t, x, x.txs[1].Hash())
		e := x.engine(t)
		token := f.Token(t, x.config.Snapshot, f.Subject, "Auditor")
		out := historyResponse(t, e, token, f.Org, "eth_getTransactionByHash", `["`+x.txs[1].Hash().Hex()+`"]`, `1`)
		if (string(out["result"]) == "null") != strict {
			t.Fatal("visibleTo transaction gate")
		}
		out = historyResponse(t, e, token, f.Org, "eth_getLogs", `[{"fromBlock":"0x1","toBlock":"0x1"}]`, `1`)
		hasHidden := strings.Contains(strings.ToLower(string(out["result"])), strings.ToLower(common.Bytes2Hex(x.hidden.Bytes())))
		if hasHidden == strict {
			t.Fatal("exact listed unlock versus strict mask", string(out["result"]))
		}
	}
	for _, role := range []string{"Auditor", "Admin", "Local"} {
		x := newHistoryEngineFixture(t, false, true, `[]`)
		historyListed(t, x, x.txs[1].Hash())
		e := x.engine(t)
		out := historyResponse(t, e, f.Token(t, x.config.Snapshot, f.Subject, role), f.Org, "eth_getLogs", `[{"fromBlock":"0x1","toBlock":"0x1"}]`, `1`)
		if string(out["result"]) != "[]" {
			t.Fatal("unknown layout bypassed by grant/admin/unlock", role, string(out["result"]))
		}
	}
}
func TestHistoryEngineAnonymousInvalidBearerColdMapsAndFinalFacts(t *testing.T) {
	x := newHistoryEngineFixture(t, false, false, historyABI)
	e := x.engine(t)
	out := historyResponse(t, e, "", "", "eth_getBlockByNumber", `["latest",true]`, `1`)
	var block map[string]json.RawMessage
	_ = json.Unmarshal(out["result"], &block)
	if string(block["transactions"]) != "[]" {
		t.Fatal("anonymous private population")
	}
	sumCalls := func() int {
		n := 0
		for _, count := range x.node.Calls() {
			n += count
		}
		return n
	}
	before := sumCalls()
	out = historyResponse(t, e, "invalid", f.Org, "eth_getBlockByNumber", `["latest",true]`, `1`)
	if out["error"] == nil || sumCalls() != before {
		t.Fatal("invalid bearer became anonymous")
	}
	bad := x.config
	bad.Clients = map[rpcengine.HistoryBindingKey]*rpcexecution.HistoryReadClient{}
	if _, err := rpcengine.NewHistory(bad); err == nil {
		t.Fatal("missing exact org source map accepted")
	}
	bad = x.config
	bad.Clients = map[rpcengine.HistoryBindingKey]*rpcexecution.HistoryReadClient{}
	for key, value := range x.config.Clients {
		bad.Clients[key] = value
	}
	bad.Clients[rpcengine.HistoryBindingKey{OrganizationID: f.Org}] = x.config.Clients[rpcengine.HistoryBindingKey{OrganizationID: f.OtherOrg}]
	if _, err := rpcengine.NewHistory(bad); err == nil {
		t.Fatal("foreign source org accepted")
	}
	token := f.Token(t, x.config.Snapshot, f.Subject, "Auditor")
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x1",true]}`)
	r := e.QueryObserved(t.Context(), rpcengine.MetadataAuthorization([]string{"Bearer " + token}), f.Org, raw)
	x.node.Reorg(true)
	if r.RequireDeliverable(t.Context(), e) == nil {
		t.Fatal("canonical change after observation delivered")
	}
	x.node.Reorg(false)
	r = e.QueryObserved(t.Context(), rpcengine.MetadataAuthorization([]string{"Bearer " + token}), f.Org, raw)
	x.wallets.facts = nil
	if r.RequireDeliverable(t.Context(), e) == nil {
		t.Fatal("changed wallet set delivered")
	}
	x.wallets.facts = []walletops.OwnershipFact{}
	x.clock.Store(f.Now + 300)
	if r.RequireDeliverable(t.Context(), e) == nil {
		t.Fatal("original token expiry reset")
	}
}

func TestHistoryEngineAliasesClaimsSelectedOrgAndOriginalIndex(t *testing.T) {
	x := newHistoryEngineFixture(t, false, false, historyABI, func(src *f.StateFixture) {
		aliases := map[string]string{}
		for k, v := range src.Methods.Aliases {
			aliases[k] = v
		}
		src.Methods.Assignable = append(src.Methods.Assignable, "bank_history", "bank_adminHistory")
		aliases["bank_history"] = "eth_getTransactionByHash"
		aliases["bank_adminHistory"] = "eth_getTransactionByHash"
		src.Methods.Aliases = aliases
		claims := map[string]string{}
		for k, v := range src.Methods.RequiredClaims {
			claims[k] = v
		}
		claims["bank_adminHistory"] = "admin"
		src.Methods.RequiredClaims = claims
		for org, groups := range src.Groups {
			for i := range groups {
				groups[i].AllowedMethods = append(groups[i].AllowedMethods, "bank_history")
				if org == f.OtherOrg && groups[i].IsOrgAdmin {
					groups[i].IsOrgAdmin = false
					groups[i].Claims = append(groups[i].Claims, "admin")
				}
				for _, claim := range groups[i].Claims {
					if claim == "admin" {
						groups[i].AllowedMethods = append(groups[i].AllowedMethods, "bank_adminHistory")
						break
					}
				}
			}
			src.Groups[org] = groups
		}
	})
	e := x.engine(t)
	token := f.Token(t, x.config.Snapshot, f.Subject, "Auditor", "Foreign")
	params := `["` + x.txs[0].Hash().Hex() + `"]`
	out := historyResponse(t, e, token, f.Org, "bank_history", params, `"alias"`)
	if string(out["result"]) == "null" || out["error"] != nil {
		t.Fatal("approved alias did not use same current operation", string(out["error"]))
	}
	out = historyResponse(t, e, token, f.Org, "bank_adminHistory", params, `1`)
	if out["error"] == nil {
		t.Fatal("Foreign org admin claim supplied BankA alias required claim")
	}
	out = historyResponse(t, e, f.Token(t, x.config.Snapshot, f.Subject, "Local"), f.Org, "bank_adminHistory", params, `1`)
	if out["error"] != nil || string(out["result"]) == "null" {
		t.Fatal("actual selected-org claim alias rejected")
	}
	// A BankB admin cannot bypass the BankA target's transaction gate, even
	// when that actor also has a genuine BankA method/read grant.
	out = historyResponse(t, e, token, f.Org, "eth_getTransactionByHash", `["`+x.txs[1].Hash().Hex()+`"]`, `1`)
	if string(out["result"]) != "null" {
		t.Fatal("cross-org admin borrowed by selected source")
	}
	loads := x.wallets.loads
	out = historyResponse(t, e, token, "", "bank_history", params, `1`)
	if out["error"] == nil || x.wallets.loads != loads {
		t.Fatal("ambiguous org reached wallet/source acquisition")
	}
	// This independently scoped original active wallet set owns only tx index1.
	// The returned block index stays1; a lookup of actual index0 stays hidden.
	x.wallets.facts[0].Address = crypto.PubkeyToAddress(f.HistoryKey(2).PublicKey)
	out = historyResponse(t, e, token, f.Org, "eth_getBlockByNumber", `["0x1",true]`, `1`)
	var block map[string]json.RawMessage
	_ = json.Unmarshal(out["result"], &block)
	var entries []map[string]json.RawMessage
	_ = json.Unmarshal(block["transactions"], &entries)
	if len(entries) != 1 || string(entries[0]["transactionIndex"]) != `"0x1"` {
		t.Fatal("block renumbered visible index", string(out["result"]))
	}
	out = historyResponse(t, e, token, f.Org, "eth_getTransactionByBlockNumberAndIndex", `["0x1","0x0"]`, `1`)
	if string(out["result"]) != "null" {
		t.Fatal("by-index treated0 as filtered array index")
	}
	out = historyResponse(t, e, token, f.Org, "eth_getTransactionByBlockNumberAndIndex", `["0x1","0x1"]`, `1`)
	if !bytes.Contains(out["result"], []byte(x.txs[1].Hash().Hex())) {
		t.Fatal("actual original index1 not delivered")
	}
}

func TestHistoryEngineReservesWholeLayoutAndBothSharePassesBeforeSQL(t *testing.T) {
	x := newHistoryEngineFixture(t, false, false, historyABI)
	x.config.QueryLimits.MaxChargedBytes = 9 << 20
	newClient := func(org string) *rpcexecution.HistoryReadClient {
		c, err := rpcexecution.NewHistoryReadClient(x.node.Transport(), x.node.Source(org), rpcexecution.Credential{}, x.config.QueryLimits)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	x.config.Default = newClient("")
	for key := range x.config.Clients {
		x.config.Clients[key] = newClient(key.OrganizationID)
	}
	e := x.engine(t)
	out := historyResponse(t, e, f.Token(t, x.config.Snapshot, f.Subject, "Auditor"), f.Org, "eth_getLogs", `[{"fromBlock":"0x1","toBlock":"0x1"}]`, `1`)
	if out["error"] != nil || string(out["result"]) == "[]" {
		t.Fatal("small bounded query rejected", string(out["error"]))
	}
	// The matcher alone reserved8MiB. Remaining source/render/current facts
	// and BOTH original/fresh share passes share the selected9MiB ceiling.
	if x.shares.lastLimit <= 0 || x.shares.lastLimit >= 512<<10 || x.shares.reads < 2 {
		t.Fatal("SQL decoder/recheck reset to independent facts ceiling", x.shares.lastLimit, x.shares.reads)
	}
}

func TestHistoryEngineReservedNamespaceAliasesRejectCold(t *testing.T) {
	for _, alias := range []string{"ops_history", "eth_fakeHistory", "engine_history"} {
		x := newHistoryEngineFixture(t, false, false, historyABI, func(src *f.StateFixture) {
			src.Methods.Assignable = append(src.Methods.Assignable, alias)
			aliases := map[string]string{}
			for k, v := range src.Methods.Aliases {
				aliases[k] = v
			}
			aliases[alias] = "eth_getTransactionByHash"
			src.Methods.Aliases = aliases
			for org, groups := range src.Groups {
				for i := range groups {
					groups[i].AllowedMethods = append(groups[i].AllowedMethods, alias)
				}
				src.Groups[org] = groups
			}
		})
		if _, err := rpcengine.NewHistory(x.config); err == nil || x.wallets.loads != 0 || len(x.node.Calls()) != 0 {
			t.Fatal("reserved alias reached actual consumer/I/O", alias, err)
		}
	}
}

func TestHistoryEngineRejectsSharePassWithWidenedSelectedAllowance(t *testing.T) {
	x := newHistoryEngineFixture(t, false, false, historyABI)
	x.shares.widenLimit = true
	e := x.engine(t)
	out := historyResponse(t, e, f.Token(t, x.config.Snapshot, f.Subject, "Auditor"), f.Org, "eth_getLogs", `[{"fromBlock":"0x1","toBlock":"0x1"}]`, `1`)
	if out["error"] == nil || out["result"] != nil {
		t.Fatal("share source replaced original bounded query allowance")
	}
}

func TestHistoryEngineParticipantOnlyBlockMethodsDoNotAcquireShares(t *testing.T) {
	x := newHistoryEngineFixture(t, false, false, historyABI)
	x.shares.unavailable = true
	e := x.engine(t)
	token := f.Token(t, x.config.Snapshot, f.Subject, "Auditor")
	for _, tc := range []struct{ method, params string }{
		{"eth_getBlockByHash", `["` + x.node.Hash().Hex() + `",true]`},
		{"eth_getBlockByNumber", `["0x1",true]`},
		{"eth_getBlockTransactionCountByHash", `["` + x.node.Hash().Hex() + `"]`},
		{"eth_getBlockTransactionCountByNumber", `["0x1"]`},
	} {
		out := historyResponse(t, e, token, f.Org, tc.method, tc.params, `1`)
		if out["error"] != nil || string(out["result"]) == "null" || x.shares.reads != 0 {
			t.Fatal("participant-only envelope touched unused shares", tc.method, string(out["error"]), x.shares.reads)
		}
	}
	// Every other history surface can consume a listing, including by-index
	// envelopes and the logs inside a block receipt array. Outage stays closed.
	for _, tc := range []struct{ method, params string }{
		{"eth_getTransactionByHash", `["` + x.txs[0].Hash().Hex() + `"]`},
		{"eth_getTransactionReceipt", `["` + x.txs[0].Hash().Hex() + `"]`},
		{"eth_getTransactionByBlockHashAndIndex", `["` + x.node.Hash().Hex() + `","0x0"]`},
		{"eth_getTransactionByBlockNumberAndIndex", `["0x1","0x0"]`},
		{"eth_getLogs", `[{"fromBlock":"0x1","toBlock":"0x1"}]`},
		{"eth_getBlockReceipts", `["0x1"]`},
	} {
		before := x.shares.reads
		out := historyResponse(t, e, token, f.Org, tc.method, tc.params, `1`)
		if out["error"] == nil || x.shares.reads <= before {
			t.Fatal("share-consuming method bypassed actual share failure", tc.method)
		}
	}
}
