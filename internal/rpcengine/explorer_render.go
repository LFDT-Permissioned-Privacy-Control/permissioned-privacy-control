package rpcengine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/explorerprivacy"
	"privacy-proxy/internal/explorerquery"
	wire "privacy-proxy/internal/explorerv2data"
	"privacy-proxy/internal/readprivacyabi"
	"privacy-proxy/internal/rpcexecution"
)

type explorerFields map[string]json.RawMessage

func fieldsOf(row explorerquery.Record) (explorerFields, error) {
	var f explorerFields
	if json.Unmarshal(row.JSON, &f) != nil {
		return nil, errExplorer
	}
	return f, nil
}
func (f explorerFields) text(k string) string { var s string; _ = json.Unmarshal(f[k], &s); return s }
func (f explorerFields) nullable(k string) *string {
	s := f.text(k)
	if s == "" {
		return nil
	}
	return &s
}
func (f explorerFields) boolean(k string) bool { var b bool; _ = json.Unmarshal(f[k], &b); return b }
func (f explorerFields) integer(k string) (uint64, error) {
	s := f.text(k)
	if s == "" {
		s = string(f[k])
	}
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		return 0, errExplorer
	}
	return n, nil
}
func (f explorerFields) quantity(k string) (*wire.Quantity, error) {
	if len(f[k]) == 0 || string(f[k]) == "null" {
		return nil, nil
	}
	s := f.text(k)
	if s == "" {
		s = string(f[k])
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 || n.String() != s {
		return nil, errExplorer
	}
	v := wire.Quantity(s)
	return &v, nil
}
func decimal(n uint64) wire.Quantity { return wire.Quantity(strconv.FormatUint(n, 10)) }
func qbig(n *big.Int) wire.Quantity {
	if n == nil {
		return "0"
	}
	return wire.Quantity(n.String())
}
func qptr(n uint64) *wire.Quantity { q := decimal(n); return &q }
func maskAddress(s string) string {
	if explorerquery.ValidAddress(strings.ToLower(s)) {
		return strings.ToLower(s)
	}
	return common.Address{}.Hex()
}
func maskAddressPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := maskAddress(*s)
	return &v
}
func maskedQuantity(s explorerdata.JSONString) *wire.Quantity {
	if s == "" {
		return nil
	}
	v := wire.Quantity(s)
	return &v
}
func metadataWire(m map[string]explorerdata.VisibilityReason) *wire.AddressMetadata {
	if len(m) == 0 {
		return nil
	}
	out := wire.AddressMetadata{}
	for k, v := range m {
		out[k] = string(v)
	}
	return &out
}

type explorerMatchedLog struct {
	row     explorerdata.Log
	abi     json.RawMessage
	emitter historyRenderEmitter
	source  rpcexecution.LocatedHistoryLog
}
type explorerRender struct {
	result           *ExplorerOperationResult
	own              map[string]bool
	matcher          *readprivacyabi.EventLayoutMatcher
	emitters         map[common.Address]historyRenderEmitter
	transactions     map[string]rpcexecution.LocatedHistoryTransaction
	receipts         map[string]rpcexecution.LocatedHistoryReceipt
	logs             map[string]explorerMatchedLog
	fields           map[string]explorerFields
	contextTransfers []explorerdata.TokenTransfer
	detailed         map[string]explorerdata.AddressVisibility
}

func newExplorerRender(r *ExplorerOperationResult, data explorerquery.Data) (*explorerRender, error) {
	x := &explorerRender{result: r, own: map[string]bool{}, emitters: map[common.Address]historyRenderEmitter{}, transactions: map[string]rpcexecution.LocatedHistoryTransaction{}, receipts: map[string]rpcexecution.LocatedHistoryReceipt{}, logs: map[string]explorerMatchedLog{}, fields: map[string]explorerFields{}, detailed: map[string]explorerdata.AddressVisibility{}}
	for _, a := range r.current.OwnAddresses() {
		x.own[strings.ToLower(a.Hex())] = true
	}
	for _, t := range r.batch.Transactions() {
		x.transactions[strings.ToLower(t.Transaction.Hash().Hex())] = t
	}
	for _, v := range r.batch.Receipts() {
		x.receipts[strings.ToLower(v.TransactionHash.Hex())] = v
	}
	for _, row := range append(append([]explorerquery.Record{}, data.Rows...), data.Context...) {
		if row.Family == explorerquery.Transactions {
			f, e := fieldsOf(row)
			if e != nil {
				return nil, e
			}
			x.fields[f.text("hash")] = f
		}
	}
	limits := readprivacyabi.DefaultLayoutLimits()
	// This reservation covers the parser, retained prepared ABI copies, and metadata
	// before any emitter acquisition; it shares the node/SQL operation ceiling.
	if err := r.batch.ReserveWorkingBytes(limits.MaxBytes); err != nil {
		return nil, err
	}
	var err error
	x.matcher, err = readprivacyabi.NewEventLayoutMatcher(limits)
	if err != nil {
		return nil, err
	}
	for _, l := range r.batch.Logs() {
		m, ok, e := x.match(l)
		if e != nil {
			return nil, e
		}
		if ok {
			x.logs[explorerprivacy.TransferLogKey(m.row.TxHash, m.row.LogIndex)] = m
		}
	}
	seenTransfers := map[string]bool{}
	for _, row := range append(append([]explorerquery.Record{}, data.Rows...), data.Context...) {
		if row.Family != explorerquery.Transfers {
			continue
		}
		if seenTransfers[row.Key] {
			continue
		}
		seenTransfers[row.Key] = true
		f, e := fieldsOf(row)
		if e != nil {
			return nil, e
		}
		if _, ok := x.transactions[f.text("tx_hash")]; !ok {
			continue
		}
		tr, ok, e := x.transfer(row)
		if e != nil {
			return nil, e
		}
		if ok {
			x.contextTransfers = append(x.contextTransfers, tr)
		}
	}
	return x, nil
}
func (x *explorerRender) visibility(address string) explorerdata.AddressVisibility {
	a := strings.ToLower(address)
	if v, ok := x.detailed[a]; ok {
		return v
	}
	v := x.result.current.Address(common.HexToAddress(a))
	x.detailed[a] = v
	return v
}
func (x *explorerRender) emitter(address common.Address) (historyRenderEmitter, error) {
	if e, ok := x.emitters[address]; ok {
		return e, nil
	}
	if len(x.emitters) >= 128 {
		return historyRenderEmitter{}, explorerquery.ErrTooBroad
	}
	if e := x.matcher.ReserveMetadata(x.result.current.EmitterMetadataCharge(address) + 128); e != nil {
		return historyRenderEmitter{}, e
	}
	e := historyRenderEmitter{metadata: x.result.current.Emitter(address)}
	var err error
	e.layouts, err = x.matcher.Prepare(e.metadata.Registry.ABI)
	if err != nil {
		return e, err
	}
	x.emitters[address] = e
	return e, nil
}
func (x *explorerRender) match(l rpcexecution.LocatedHistoryLog) (explorerMatchedLog, bool, error) {
	e, err := x.emitter(l.Log.Address)
	if err != nil {
		return explorerMatchedLog{}, false, err
	}
	topics := []string{}
	for _, t := range l.Log.Topics {
		topics = append(topics, strings.ToLower(t.Hex()))
	}
	data := "0x" + hex.EncodeToString(l.Log.Data)
	matched, ok, err := x.matcher.MatchPrepared(e.layouts, topics, data)
	if err != nil || !ok {
		return explorerMatchedLog{}, false, err
	}
	row := explorerdata.Log{TxHash: strings.ToLower(l.TransactionHash.Hex()), LogIndex: int(l.Log.LogIndex), Address: strings.ToLower(l.Log.Address.Hex()), Data: data, BlockNumber: l.Location.BlockNumber, Removed: l.Removed}
	pointers := []**string{&row.Topic0, &row.Topic1, &row.Topic2, &row.Topic3}
	for i, t := range topics {
		v := t
		*pointers[i] = &v
	}
	return explorerMatchedLog{row: row, abi: matched, emitter: e, source: l}, true, nil
}
func (x *explorerRender) opts(hash string, target string) explorerprivacy.RedactOpts {
	listed := x.result.current.Listed(common.HexToHash(hash))
	visible := listed
	return explorerprivacy.RedactOpts{VisibleTxHashes: map[string]bool{hash: visible}, ListedTxHashes: map[string]bool{hash: listed}, ViewerIsAdmin: explorerquery.ValidAddress(target) && x.result.current.AdminForDataset(common.HexToAddress(target))}
}
func (x *explorerRender) rowID(row explorerquery.Record) string {
	h := hmac.New(sha256.New, x.result.owner.config.PseudonymKey)
	raw, _ := json.Marshal(struct {
		Domain string
		Source explorerquery.Binding
		Family explorerquery.Family
		Key    string
	}{"ops-explorer-row/v1", x.result.owner.metadata.Binding, row.Family, row.Key})
	h.Write(raw)
	return "row:" + hex.EncodeToString(h.Sum(nil))
}
func (x *explorerRender) parent(hash string) (rpcexecution.LocatedHistoryTransaction, rpcexecution.LocatedHistoryReceipt, error) {
	t, ok := x.transactions[hash]
	r, yes := x.receipts[hash]
	if !ok || !yes {
		return t, r, errExplorer
	}
	return t, r, nil
}
func (x *explorerRender) logParticipant(hash string) bool {
	for _, m := range x.logs {
		if m.row.TxHash != hash || m.row.Topic0 == nil {
			continue
		}
		topics := []*string{m.row.Topic0, m.row.Topic1, m.row.Topic2, m.row.Topic3}
		for _, slot := range readprivacyabi.ParticipantSlots(*m.row.Topic0) {
			if slot < len(topics) && topics[slot] != nil {
				if a, ok := readprivacyabi.ExtractTopicAddress(*topics[slot]); ok && x.own[a] {
					return true
				}
			}
		}
	}
	return false
}
func (x *explorerRender) shadowTransaction(hash string) (explorerdata.Transaction, error) {
	t, r, err := x.parent(hash)
	if err != nil {
		return explorerdata.Transaction{}, err
	}
	v := t.Transaction
	from := strings.ToLower(v.From().Hex())
	to := (*string)(nil)
	if a, ok := v.To(); ok {
		s := strings.ToLower(a.Hex())
		to = &s
	}
	n := v.Nonce()
	out := explorerdata.Transaction{Hash: hash, BlockNumber: t.Location.BlockNumber, TxIndex: int(t.Location.TransactionIndex), From: from, To: to, Value: explorerdata.JSONString(v.Value().String()), InputData: "0x" + hex.EncodeToString(v.Input()), Nonce: &n, TxType: int(v.Type())}
	if a, ok := r.Receipt.ContractAddress(); ok {
		s := strings.ToLower(a.Hex())
		out.ContractAddress = &s
	}
	x.visibility(from)
	if to != nil {
		x.visibility(*to)
	}
	if out.ContractAddress != nil {
		x.visibility(*out.ContractAddress)
	}
	if f, ok := x.fields[hash]; ok {
		block, e := f.integer("block_number")
		index, ie := f.integer("tx_index")
		value, ve := f.quantity("value")
		if e != nil || ie != nil || ve != nil || value == nil || block != t.Location.BlockNumber || index != uint64(t.Location.TransactionIndex) || f.text("from_address") != from || f.text("to_address") != func() string {
			if to == nil {
				return ""
			}
			return *to
		}() || string(*value) != v.Value().String() || !strings.EqualFold(f.text("input_data"), out.InputData) {
			return out, errExplorer
		}
	}
	return out, nil
}
func (x *explorerRender) transaction(row explorerquery.Record) (any, bool, error) {
	f, e := fieldsOf(row)
	if e != nil {
		return nil, false, e
	}
	hash := f.text("hash")
	shadow, e := x.shadowTransaction(hash)
	if e != nil {
		return nil, false, e
	}
	opts := x.opts(hash, func() string {
		if shadow.To == nil {
			return ""
		}
		return *shadow.To
	}())
	union := false
	for _, tr := range x.contextTransfers {
		if tr.TxHash == hash && (x.visibility(tr.From).Level == explorerdata.VisibilityFull || x.visibility(tr.To).Level == explorerdata.VisibilityFull) {
			union = true
			break
		}
	}
	if !x.result.current.Profile().Strict() {
		opts.VisibleTxHashes[hash] = opts.ListedTxHashes[hash] || union
	}
	label := x.result.request.operation.Label
	if (label == "explorer.transactions" || label == "explorer.transactions_page" || label == "explorer.stats" || label == "explorer.tx_history") && !x.result.current.Profile().Strict() && !opts.ListedTxHashes[hash] && !union && x.visibility(shadow.From).Level != explorerdata.VisibilityFull && (shadow.To == nil || x.visibility(*shadow.To).Level != explorerdata.VisibilityFull) {
		return nil, false, nil
	}
	abiParticipant := false
	if shadow.To != nil {
		em, er := x.emitter(common.HexToAddress(*shadow.To))
		if er != nil {
			return nil, false, er
		}
		abiParticipant = readprivacyabi.IsViewerInCalldataABI(shadow.InputData, string(em.metadata.Registry.ABI), x.own)
	}
	out, e := explorerprivacy.RedactTransactions(explorerprivacy.TransactionInput{Rows: []explorerdata.Transaction{shadow}, Profile: x.result.current.Profile(), Detailed: x.detailed, ViewerAddresses: x.own, LogParticipants: map[string]bool{hash: x.logParticipant(hash)}, CalldataParticipants: []bool{abiParticipant}, PseudonymKey: x.result.owner.config.PseudonymKey}, opts)
	if e != nil || len(out) == 0 {
		return nil, false, e
	}
	red := out[0]
	t, r, _ := x.parent(hash)
	v := t.Transaction
	fees := v.Fees()
	ix := t.Location.TransactionIndex
	gas := v.GasLimit()
	result := wire.Transaction{Hash: hash, BlockNumber: qptr(t.Location.BlockNumber), TxIndex: &ix, From: maskAddress(red.From), To: maskAddressPtr(red.To), ContractAddress: maskAddressPtr(red.ContractAddress), Value: maskedQuantity(red.Value), GasUsed: qptr(r.Receipt.GasUsed()), GasPrice: qbig(t.GasPrice), GasLimit: qptr(gas), TxType: v.Type(), InputData: wire.Hex(red.InputData), AddressMetadata: metadataWire(red.AddressMetadata)}
	if red.InputData == "" {
		result.InputData = "0x"
	}
	if red.Nonce != nil {
		result.Nonce = qptr(*red.Nonce)
	}
	if fees.MaxFeePerGas != nil {
		q := qbig(fees.MaxFeePerGas)
		result.MaxFeePerGas = &q
	}
	if fees.MaxPriorityFeePerGas != nil {
		q := qbig(fees.MaxPriorityFeePerGas)
		result.MaxPriorityFeePerGas = &q
	}
	if fees.MaxFeePerBlobGas != nil {
		q := qbig(fees.MaxFeePerBlobGas)
		result.MaxFeePerBlobGas = &q
	}
	if status, ok := r.Receipt.Status(); ok {
		result.Status = &status
	}
	if root, ok := r.Receipt.PostStateRoot(); ok {
		s := strings.ToLower(root.Hex())
		result.PostStateRoot = &s
	}
	if header, ok := x.result.batch.Header(t.Location.BlockNumber, t.Location.BlockHash); ok {
		result.BlockTimestamp = qptr(header.Time)
	} else {
		return nil, false, errExplorer
	}
	result.CreatedAt = f.nullable("created_at")
	status, hasStatus := r.Receipt.Status()
	cats := explorerTransactionCategories(shadow.IsContractCreation(), v.Value(), v.Input(), hasStatus && status == 1)
	if !x.result.current.Profile().Strict() {
		count := uint64(0)
		for _, tr := range x.contextTransfers {
			if tr.TxHash == hash {
				if _, ok, e := x.renderTransfer(tr); e != nil {
					return nil, false, e
				} else if ok {
					count++
				}
			}
		}
		if count > 0 {
			cats = append(cats, "token_transfer")
			result.TokenTransferCount = qptr(count)
		}
	}
	result.TxCategories = &cats
	if x.result.request.category != "" {
		found := false
		for _, c := range cats {
			if c == x.result.request.category {
				found = true
			}
		}
		if !found {
			return nil, false, nil
		}
	}
	return result, true, nil
}

// Keep the existing indexer's category meanings, deriving them from the
// qualified signed envelope and receipt rather than mutable category bits.
func explorerTransactionCategories(creation bool, value *big.Int, input []byte, successful bool) []string {
	categories := []string{}
	if value != nil && value.Sign() > 0 && len(input) == 0 {
		categories = append(categories, "coin_transfer")
	}
	if creation && successful {
		categories = append(categories, "contract_creation")
	}
	if !creation && len(input) >= 4 {
		categories = append(categories, "contract_call")
	}
	return categories
}

func (x *explorerRender) transfer(row explorerquery.Record) (explorerdata.TokenTransfer, bool, error) {
	f, e := fieldsOf(row)
	if e != nil {
		return explorerdata.TokenTransfer{}, false, e
	}
	hash := f.text("tx_hash")
	_, _, e = x.parent(hash)
	if e != nil {
		return explorerdata.TokenTransfer{}, false, e
	}
	idx, e := f.integer("log_index")
	if e != nil || idx > 1<<32-1 {
		return explorerdata.TokenTransfer{}, false, errExplorer
	}
	bn, e := f.integer("block_number")
	if e != nil {
		return explorerdata.TokenTransfer{}, false, e
	}
	value, e := f.quantity("value")
	if e != nil || value == nil {
		return explorerdata.TokenTransfer{}, false, errExplorer
	}
	t := explorerdata.TokenTransfer{TxHash: hash, LogIndex: int(idx), TokenAddress: f.text("token_address"), From: f.text("from_address"), To: f.text("to_address"), Value: explorerdata.JSONString(*value), BlockNumber: bn, TransferType: f.text("transfer_type"), TokenType: f.text("token_type"), IsInternal: f.boolean("is_internal"), TokenID: f.nullable("token_id")}
	if !explorerquery.ValidAddress(t.From) || !explorerquery.ValidAddress(t.To) || !explorerquery.ValidAddress(t.TokenAddress) {
		return t, false, errExplorer
	}
	m, ok := x.logs[explorerprivacy.TransferLogKey(hash, int(idx))]
	if !ok {
		return t, false, nil
	}
	if m.row.Address != t.TokenAddress || bn != m.row.BlockNumber {
		return t, false, errExplorer
	}
	parsed, err := abi.JSON(strings.NewReader(string(m.abi)))
	if err != nil {
		return t, false, errExplorer
	}
	ev, err := parsed.EventByID(common.HexToHash(*m.row.Topic0))
	if err != nil {
		return t, false, errExplorer
	}
	payload, err := ev.Inputs.NonIndexed().Unpack(m.source.Log.Data)
	if err != nil {
		return t, false, errExplorer
	}
	topics := m.source.Log.Topics
	address := func(i int) string {
		if i >= len(topics) {
			return ""
		}
		return strings.ToLower(common.BytesToAddress(topics[i][12:]).Hex())
	}
	zero := strings.ToLower(common.Address{}.Hex())
	match := false
	amount := func(v any) string {
		n, ok := v.(*big.Int)
		if !ok || n == nil {
			return ""
		}
		return n.String()
	}
	switch ev.Name {
	case "Transfer":
		if len(topics) == 3 && len(payload) == 1 {
			match = t.From == address(1) && t.To == address(2) && string(t.Value) == amount(payload[0]) && t.TokenID == nil
		}
		if len(topics) == 4 && len(payload) == 0 {
			id := new(big.Int).SetBytes(topics[3][:]).String()
			match = t.From == address(1) && t.To == address(2) && t.TokenID != nil && *t.TokenID == id && string(t.Value) == "1"
		}
	case "TransferSingle":
		match = len(topics) == 4 && len(payload) == 2 && t.From == address(2) && t.To == address(3) && t.TokenID != nil && *t.TokenID == amount(payload[0]) && string(t.Value) == amount(payload[1])
	case "TransferBatch":
		if len(topics) == 4 && len(payload) == 2 && t.From == address(2) && t.To == address(3) && t.TokenID != nil {
			ids, yes := payload[0].([]*big.Int)
			values, also := payload[1].([]*big.Int)
			if yes && also && len(ids) == len(values) {
				for i, id := range ids {
					if id.String() == *t.TokenID && values[i].String() == string(t.Value) {
						match = true
					}
				}
			}
		}
	case "Deposit":
		match = len(payload) == 1 && t.From == zero && t.To == address(1) && string(t.Value) == amount(payload[0])
	case "Withdrawal":
		match = len(payload) == 1 && t.From == address(1) && t.To == zero && string(t.Value) == amount(payload[0])
	default:
		return t, false, nil
	}
	if !match {
		return t, false, errExplorer
	}
	x.visibility(t.From)
	x.visibility(t.To)
	return t, true, nil
}
func (x *explorerRender) renderTransfer(t explorerdata.TokenTransfer) (explorerdata.TokenTransfer, bool, error) {
	m, ok := x.logs[explorerprivacy.TransferLogKey(t.TxHash, t.LogIndex)]
	if !ok {
		return t, false, nil
	}
	opts := x.opts(t.TxHash, t.TokenAddress)
	strict := map[string]bool{}
	if x.result.current.Profile().Strict() {
		_, admitted, e := x.renderLog(m)
		if e != nil {
			return t, false, e
		}
		strict[explorerprivacy.TransferLogKey(t.TxHash, t.LogIndex)] = admitted
	}
	out := explorerprivacy.RedactTransfers(explorerprivacy.TransferInput{Rows: []explorerdata.TokenTransfer{t}, Profile: x.result.current.Profile(), Detailed: x.detailed, ViewerAddresses: x.own, StrictAdmitted: strict, PseudonymKey: x.result.owner.config.PseudonymKey}, opts)
	if len(out.Rows) == 0 {
		return t, false, nil
	}
	eventAccess := m.emitter.metadata.Admin || m.emitter.metadata.HasGrant && (m.emitter.metadata.Rules != nil && (m.emitter.metadata.Rules.Wildcard || len(m.emitter.metadata.Rules.Rules) > 0))
	filtered, e := explorerprivacy.ApplyTransferEventAccess(out.Rows, out.EventAccessExempt, map[string]bool{t.TokenAddress: eventAccess})
	if e != nil || len(filtered) == 0 {
		return t, false, e
	}
	return filtered[0], true, nil
}
func (x *explorerRender) renderLog(m explorerMatchedLog) (explorerdata.Log, bool, error) {
	e := m.emitter.metadata
	addr := m.row.Address
	level := x.visibility(addr)
	// Plain Full can come from a wallet, never substitute it for event authority.
	if !e.HasGrant && !e.Admin && !(e.VisibleToUnlock && x.result.current.Listed(m.source.TransactionHash)) {
		return m.row, false, nil
	}
	vis := explorerdata.VisibilityMap{addr: level.Level}
	meta := map[string]explorerdata.VisibilityReason{addr: level.Reason}
	for _, a := range readprivacyabi.ExtractLogAddresses([]*string{m.row.Topic0, m.row.Topic1, m.row.Topic2, m.row.Topic3}, m.row.Data, m.abi, m.row.Topic0) {
		v := x.visibility(a)
		vis[a] = v.Level
		meta[a] = v.Reason
	}
	rules := explorerprivacy.EventRulesResolution{}
	if e.Rules != nil {
		rules.Wildcard = e.Rules.Wildcard
		for _, r := range e.Rules.Rules {
			rules.Rules = append(rules.Rules, explorerprivacy.EventRuleInfo{Topic0: r.Topic0, ParamRules: r.ParamRules})
		}
	}
	parent, err := x.shadowTransaction(m.row.TxHash)
	if err != nil {
		return m.row, false, err
	}
	participant := x.own[parent.From] || parent.To != nil && x.own[*parent.To]
	opts := x.opts(m.row.TxHash, addr)
	out, err := explorerprivacy.RedactLogs(explorerprivacy.LogInput{Rows: []explorerdata.Log{m.row}, Profile: x.result.current.Profile(), Visibility: vis, MasterMetadata: meta, ViewerAddresses: x.own, Participant: participant, Rules: map[string]explorerprivacy.EventRulesResolution{addr: rules}, RulesResolved: map[string]bool{addr: true}, AdminContracts: map[string]bool{addr: e.Admin}, UnlockableContracts: map[string]bool{addr: e.VisibleToUnlock}, AllowDynamicPayload: map[string]bool{addr: e.Registry.EventsAllowDynamicPayload}, ContractABIs: map[string]json.RawMessage{addr: m.abi}, ResolvedABIs: map[string]string{addr: string(m.abi)}, PseudonymKey: x.result.owner.config.PseudonymKey}, &opts)
	if err != nil || len(out) == 0 {
		return m.row, false, err
	}
	return out[0], true, nil
}
func (x *explorerRender) transferWire(row explorerquery.Record) (any, bool, error) {
	t, ok, e := x.transfer(row)
	if e != nil || !ok {
		return nil, false, e
	}
	t, ok, e = x.renderTransfer(t)
	if e != nil || !ok {
		return nil, false, e
	}
	f, _ := fieldsOf(row)
	ts, e := f.quantity("timestamp")
	if e != nil {
		return nil, false, e
	}
	var id *wire.Quantity
	if t.TokenID != nil {
		v := wire.Quantity(*t.TokenID)
		id = &v
	}
	return wire.TokenTransfer{ID: x.rowID(row), TxHash: t.TxHash, LogIndex: uint32(t.LogIndex), TokenAddress: t.TokenAddress, From: maskAddress(t.From), To: maskAddress(t.To), Value: maskedQuantity(t.Value), BlockNumber: decimal(t.BlockNumber), Timestamp: ts, TransferType: t.TransferType, TokenType: t.TokenType, TokenID: id, IsInternal: t.IsInternal, AddressMetadata: metadataWire(t.AddressMetadata)}, true, nil
}
func (x *explorerRender) logWire(row explorerquery.Record) (any, bool, error) {
	f, e := fieldsOf(row)
	if e != nil {
		return nil, false, e
	}
	hash := f.text("tx_hash")
	n, e := f.integer("log_index")
	if e != nil || n > 1<<32-1 {
		return nil, false, errExplorer
	}
	m, ok := x.logs[explorerprivacy.TransferLogKey(hash, int(n))]
	if !ok {
		return nil, false, nil
	}
	bn, e := f.integer("block_number")
	if e != nil || bn != m.row.BlockNumber || f.text("address") != m.row.Address || f.text("data") != m.row.Data || f.boolean("removed") != m.row.Removed {
		return nil, false, errExplorer
	}
	for i, k := range []string{"topic0", "topic1", "topic2", "topic3"} {
		ts := []*string{m.row.Topic0, m.row.Topic1, m.row.Topic2, m.row.Topic3}
		actual := ""
		if ts[i] != nil {
			actual = *ts[i]
		}
		if f.text(k) != actual {
			return nil, false, errExplorer
		}
	}
	red, ok, e := x.renderLog(m)
	if e != nil || !ok {
		return nil, false, e
	}
	ts, e := f.quantity("timestamp")
	if e != nil {
		return nil, false, e
	}
	data := red.Data
	if data == "" {
		data = "0x"
	}
	return wire.Log{ID: x.rowID(row), TxHash: hash, LogIndex: uint32(n), Address: maskAddress(red.Address), Topic0: red.Topic0, Topic1: red.Topic1, Topic2: red.Topic2, Topic3: red.Topic3, Data: wire.Hex(data), BlockNumber: decimal(bn), Timestamp: ts, Removed: red.Removed, AddressMetadata: metadataWire(red.AddressMetadata)}, true, nil
}
func (x *explorerRender) internalWire(row explorerquery.Record) (any, bool, error) {
	f, e := fieldsOf(row)
	if e != nil {
		return nil, false, e
	}
	hash := f.text("tx_hash")
	parent, e := x.shadowTransaction(hash)
	if e != nil {
		return nil, false, e
	}
	bn, e := f.integer("block_number")
	if e != nil || bn != parent.BlockNumber {
		return nil, false, errExplorer
	}
	value, e := f.quantity("value")
	if e != nil || value == nil {
		return nil, false, errExplorer
	}
	from, to := f.text("from_address"), f.nullable("to_address")
	if !explorerquery.ValidAddress(from) || to != nil && !explorerquery.ValidAddress(*to) {
		return nil, false, errExplorer
	}
	x.visibility(from)
	if to != nil {
		x.visibility(*to)
	}
	in := explorerdata.InternalTransaction{TxHash: hash, From: from, To: to, Value: explorerdata.JSONString(*value), Input: f.nullable("input"), Output: f.nullable("output"), Error: f.nullable("error"), BlockNumber: bn, TraceAddress: f.text("trace_address"), CallType: f.text("call_type")}
	opts := x.opts(hash, func() string {
		if parent.To == nil {
			return ""
		}
		return *parent.To
	}())
	if x.result.request.operation.Label == "explorer.transaction_internal" {
		opts.ParentParticipants = []string{parent.From}
		if parent.To != nil {
			opts.ParentParticipants = append(opts.ParentParticipants, *parent.To)
		}
	}
	out, e := explorerprivacy.RedactInternalTransactions(explorerprivacy.InternalInput{Rows: []explorerdata.InternalTransaction{in}, Profile: x.result.current.Profile(), Detailed: x.detailed, ViewerAddresses: x.own, Parents: map[string]*explorerdata.Transaction{hash: &parent}, PseudonymKey: x.result.owner.config.PseudonymKey}, opts)
	if e != nil || len(out) == 0 {
		return nil, false, e
	}
	red := out[0]
	gas, e := f.quantity("gas")
	if e != nil {
		return nil, false, e
	}
	used, e := f.quantity("gas_used")
	if e != nil {
		return nil, false, e
	}
	ts, e := f.quantity("timestamp")
	if e != nil {
		return nil, false, e
	}
	var input, output *wire.Hex
	if red.Input != nil {
		v := wire.Hex(*red.Input)
		input = &v
	}
	if red.Output != nil {
		v := wire.Hex(*red.Output)
		output = &v
	}
	return wire.InternalTransaction{ID: x.rowID(row), TxHash: hash, BlockNumber: decimal(bn), TraceAddress: red.TraceAddress, From: maskAddress(red.From), To: maskAddressPtr(red.To), Value: maskedQuantity(red.Value), Gas: gas, GasUsed: used, Input: input, Output: output, CallType: red.CallType, Error: red.Error, Timestamp: ts, AddressMetadata: metadataWire(red.AddressMetadata)}, true, nil
}
func (x *explorerRender) other(row explorerquery.Record) (any, bool, error) {
	f, e := fieldsOf(row)
	if e != nil {
		return nil, false, e
	}
	address := f.text("address")
	full := func(a string) bool {
		return explorerquery.ValidAddress(a) && x.visibility(a).Level == explorerdata.VisibilityFull
	}
	switch row.Family {
	case explorerquery.Blocks:
		n, e := f.integer("number")
		if e != nil {
			return nil, false, e
		}
		hash := f.text("hash")
		h, ok := x.result.batch.Header(n, common.HexToHash(hash))
		if !ok {
			return nil, false, errExplorer
		}
		out := wire.Block{Number: decimal(n), Hash: hash, ParentHash: strings.ToLower(h.ParentHash.Hex()), Timestamp: decimal(h.Time), GasLimit: decimal(h.GasLimit), Difficulty: qbig(h.Difficulty), Nonce: wire.Hex("0x" + hex.EncodeToString(h.Nonce[:])), Miner: strings.ToLower(h.Coinbase.Hex()), ExtraData: wire.Hex("0x" + hex.EncodeToString(h.Extra)), StateRoot: strings.ToLower(h.Root.Hex()), TransactionsRoot: strings.ToLower(h.TxHash.Hex()), ReceiptsRoot: strings.ToLower(h.ReceiptHash.Hex()), CreatedAt: f.text("created_at")}
		if h.BaseFee != nil {
			q := qbig(h.BaseFee)
			out.BaseFeePerGas = &q
		}
		return out, true, nil
	case explorerquery.Tokens:
		if !full(address) {
			return nil, false, nil
		}
		if x.result.request.tokenType != "" && f.text("token_type") != x.result.request.tokenType {
			return nil, false, nil
		}
		n, e := f.integer("decimals")
		if e != nil || n > 255 {
			return nil, false, errExplorer
		}
		bn, e := f.quantity("block_number")
		if e != nil || bn == nil {
			return nil, false, errExplorer
		}
		out := wire.Token{Address: address, Symbol: f.text("symbol"), Name: f.nullable("name"), Decimals: uint32(n), TokenType: f.text("token_type"), BlockNumber: *bn, CreatedAt: f.text("created_at"), OffChainUpdatedAt: f.nullable("off_chain_updated_at"), CreationTx: f.nullable("creation_tx"), L1Address: f.nullable("l1_address")}
		return out, true, nil
	case explorerquery.Balances:
		if !full(address) || !full(f.text("token_address")) {
			return nil, false, nil
		}
		balance, e := f.quantity("balance")
		if e != nil || balance == nil {
			return nil, false, errExplorer
		}
		block, e := f.quantity("block_number")
		if e != nil || block == nil {
			return nil, false, errExplorer
		}
		return wire.Balance{Address: address, TokenAddress: f.text("token_address"), BlockNumber: *block, Balance: *balance}, true, nil
	case explorerquery.Holders:
		if !full(x.result.request.query.Token) || !full(address) {
			return nil, false, nil
		}
		balance, e := f.quantity("balance")
		if e != nil || balance == nil {
			return nil, false, errExplorer
		}
		out := wire.TokenHolder{Address: address, Balance: *balance}
		if _, ok := x.result.current.OriginalView().Contract(common.HexToAddress(address)); ok {
			v := true
			out.IsContract = &v
		}
		return out, true, nil
	case explorerquery.Addresses:
		if !full(address) {
			return nil, false, nil
		}
		out := wire.AddressStats{Address: address}
		first, e := f.quantity("first_seen")
		if e != nil {
			return nil, false, e
		}
		last, e := f.quantity("last_seen")
		if e != nil {
			return nil, false, e
		}
		out.FirstSeen, out.LastSeen = first, last
		return out, true, nil
	case explorerquery.Search:
		switch f.text("kind") {
		case "transaction":
			v := f.text("value")
			if _, ok, e := x.transaction(explorerquery.Record{Family: explorerquery.Transactions, JSON: func() json.RawMessage { b, _ := json.Marshal(x.fields[v]); return b }()}); e != nil || !ok {
				return nil, false, e
			}
			return wire.SearchSuggestion{Type: "transaction", Value: v}, true, nil
		case "address", "token", "contract":
			v := f.text("value")
			if full(v) {
				return wire.SearchSuggestion{Type: f.text("kind"), Value: v}, true, nil
			}
		}
		return nil, false, nil
	}
	return nil, false, errExplorer
}
func (x *explorerRender) render(data explorerquery.Data, count int) ([]byte, error) {
	items := []any{}
	var last *explorerquery.Position
	processed := 0
	moreVisible := false
	for i, row := range data.Rows[:count] {
		var value any
		var ok bool
		var err error
		switch row.Family {
		case explorerquery.Transactions:
			value, ok, err = x.transaction(row)
		case explorerquery.Transfers:
			value, ok, err = x.transferWire(row)
		case explorerquery.Internals:
			value, ok, err = x.internalWire(row)
		case explorerquery.Logs:
			value, ok, err = x.logWire(row)
		default:
			value, ok, err = x.other(row)
		}
		if err != nil {
			return nil, err
		}
		if ok && len(items) == x.result.request.limit {
			moreVisible = true
			break
		}
		processed = i + 1
		pos := row.Position
		last = &pos
		if ok {
			items = append(items, value)
		}
	}
	request := x.result.request
	if !request.collection && request.operation.Label != "explorer.stats" {
		if len(items) == 0 {
			return []byte("null"), nil
		}
		return json.Marshal(items[0])
	}
	page := wire.PageInfo{Population: wire.Population}
	exhausted := data.Exhausted && processed == len(data.Rows) && count == len(data.Rows) && !moreVisible
	if exhausted {
		v := false
		page.HasMore = &v
	} else {
		page.ScanLimited = !moreVisible
		if moreVisible {
			v := true
			page.HasMore = &v
		}
		if last == nil {
			return nil, explorerquery.ErrTooBroad
		}
		next, e := x.result.owner.sealExplorerCursor(x.result, *last)
		if e != nil {
			return nil, e
		}
		page.Next = &next
	}
	if request.operation.Label == "explorer.stats" || request.operation.Label == "explorer.tx_history" {
		page.Coverage = wire.ObservedVisiblePage
		if request.operation.Label == "explorer.stats" {
			stats, err := observedExplorerStats(items, page)
			if err != nil {
				return nil, err
			}
			return json.Marshal(stats)
		}
		points, err := observedExplorerHistory(items, request.interval)
		if err != nil {
			return nil, err
		}
		return json.Marshal(wire.Page[wire.TxHistoryPoint]{Items: points, Page: page})
	}
	return json.Marshal(wire.Page[any]{Items: items, Page: page})
}

// Aggregates describe only the emitted visible transaction page, after its
// lookahead was removed. They do not certify an index or all-history total.
func observedExplorerStats(items []any, page wire.PageInfo) (wire.ChainStats, error) {
	blocks, addresses := map[wire.Quantity]bool{}, map[string]bool{}
	for _, item := range items {
		tx, ok := item.(wire.Transaction)
		if !ok || tx.BlockNumber == nil {
			return wire.ChainStats{}, errExplorer
		}
		blocks[*tx.BlockNumber] = true
		for _, address := range []*string{&tx.From, tx.To} {
			if address != nil && *address != "0x"+strings.Repeat("0", 40) && explorerquery.ValidAddress(*address) {
				addresses[*address] = true
			}
		}
	}
	return wire.ChainStats{PrivacyEnabled: true, ObservedTransactions: decimal(uint64(len(items))), ObservedBlocks: decimal(uint64(len(blocks))), ObservedParticipantAddresses: decimal(uint64(len(addresses))), Page: page}, nil
}

func observedExplorerHistory(items []any, interval string) ([]wire.TxHistoryPoint, error) {
	span := uint64(86400)
	switch interval {
	case "hour":
		span = 3600
	case "day":
	case "week":
		span = 604800
	default:
		return nil, errExplorer
	}
	counts := map[uint64]uint64{}
	for _, item := range items {
		tx, ok := item.(wire.Transaction)
		if !ok || tx.BlockTimestamp == nil {
			return nil, errExplorer
		}
		stamp, err := strconv.ParseUint(string(*tx.BlockTimestamp), 10, 64)
		if err != nil {
			return nil, errExplorer
		}
		offset := stamp % span
		if interval == "week" {
			offset = (offset + 3*86400) % span
		}
		start := uint64(0)
		if stamp >= offset {
			start = stamp - offset
		}
		counts[start]++
	}
	starts := make([]uint64, 0, len(counts))
	for stamp := range counts {
		starts = append(starts, stamp)
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	points := make([]wire.TxHistoryPoint, 0, len(starts))
	for _, stamp := range starts {
		points = append(points, wire.TxHistoryPoint{Timestamp: decimal(stamp), Count: decimal(counts[stamp])})
	}
	return points, nil
}
