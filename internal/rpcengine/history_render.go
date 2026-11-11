package rpcengine

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/readprivacyabi"
	"privacy-proxy/internal/rpcexecution"
)

type historyRender struct {
	current  *historyfacts.Current
	profile  readprivacy.ReadProfile
	own      map[string]bool
	matcher  *readprivacyabi.EventLayoutMatcher
	self     *readprivacyabi.IndexedSelfMatcher
	emitters map[common.Address]historyRenderEmitter
}
type historyRenderEmitter struct {
	metadata historyfacts.Emitter
	layouts  *readprivacyabi.EventLayouts
}

func newHistoryRender(current *historyfacts.Current, o *rpcexecution.HistoryReadObservation) (*historyRender, error) {
	r := &historyRender{current: current, profile: readprivacy.ReadProfileStrict, own: map[string]bool{}, emitters: map[common.Address]historyRenderEmitter{}}
	if current == nil {
		return r, nil
	}
	r.profile = current.Profile()
	for _, a := range current.OwnAddresses() {
		r.own[strings.ToLower(a.Hex())] = true
	}
	hasLogs := o.HasLogs()
	if hasLogs {
		limits := readprivacyabi.DefaultLayoutLimits()
		if err := o.ReserveWorkingBytes(limits.MaxBytes); err != nil {
			return nil, err
		}
		var err error
		r.matcher, err = readprivacyabi.NewEventLayoutMatcher(limits)
		if err != nil {
			return nil, err
		}
		r.self = readprivacyabi.NewIndexedSelfMatcher()
	}
	return r, nil
}
func (r *historyRender) participant(t rpcexecution.HistoryTransaction) bool {
	if r.own[strings.ToLower(t.From().Hex())] {
		return true
	}
	to, ok := t.To()
	return ok && r.own[strings.ToLower(to.Hex())]
}
func (r *historyRender) admin(t rpcexecution.HistoryTransaction) bool {
	if r.current == nil {
		return false
	}
	to, ok := t.To()
	return ok && r.current.AdminForDataset(to)
}
func (r *historyRender) listed(hash common.Hash) bool {
	return r.current != nil && r.current.Listed(hash)
}
func (r *historyRender) admit(t rpcexecution.HistoryTransaction, surface readprivacy.TxSurface, entitled int) bool {
	_, call := t.To()
	return readprivacy.DecideTxEnvelope(r.profile, readprivacy.TxEnvelopeFacts{Surface: surface, IsParticipant: r.participant(t), IsAdminOnTo: r.admin(t), InVisibleTo: r.listed(t.Hash()), EntitledLogs: entitled, IsDeployment: !call})
}
func (r *historyRender) renderRPC(o *rpcexecution.HistoryReadObservation, q rpcexecution.HistoryReadQuery) (json.RawMessage, error) {
	if o.Kind() == rpcexecution.HistoryNotFound {
		return json.RawMessage("null"), nil
	}
	var err error
	txs := o.Transactions()
	receipts := o.Receipts()
	var value any
	switch q.Method() {
	case rpcexecution.HistoryTransactionByHash, rpcexecution.HistoryTransactionByHashIndex, rpcexecution.HistoryTransactionByNumberIndex:
		if len(txs) != 1 {
			return nil, errHistory
		}
		if r.admit(txs[0].Transaction, readprivacy.TxSurfaceTransaction, 0) {
			value, err = historyRPCTransaction(txs[0])
		}
	case rpcexecution.HistoryTransactionReceipt:
		if len(txs) != 1 || len(receipts) != 1 {
			return nil, errHistory
		}
		value, err = r.receipt(txs[0], receipts[0], readprivacy.TxSurfaceReceipt)
	case rpcexecution.HistoryBlockByHash, rpcexecution.HistoryBlockByNumber:
		var block map[string]any
		if data, ok := o.BlockData(); ok {
			raw, e := data.Header.MarshalJSON()
			if e != nil {
				return nil, e
			}
			if json.Unmarshal(raw, &block) != nil {
				return nil, errHistory
			}
			block["uncles"], block["withdrawals"] = data.Uncles, data.Withdrawals
			if data.Withdrawals == nil {
				delete(block, "withdrawals")
			}
			historyOptionalBlockFields(block, data.ReportedSize, data.SizePresence, data.TotalDifficulty, data.TDPresence)
		} else if p, ok := o.PendingBlock(); ok {
			raw, e := p.Header.MarshalJSON()
			if e != nil {
				return nil, e
			}
			if json.Unmarshal(raw, &block) != nil {
				return nil, errHistory
			}
			if p.HashPresent {
				block["hash"] = p.Hash.Hex()
			} else {
				block["hash"] = nil
			}
			if !p.NoncePresent {
				block["nonce"] = nil
			}
			if !p.MinerPresent {
				block["miner"] = nil
			}
			block["uncles"], block["withdrawals"] = p.Uncles, p.Withdrawals
			if p.Withdrawals == nil {
				delete(block, "withdrawals")
			}
			historyOptionalBlockFields(block, p.ReportedSize, p.SizePresence, p.TotalDifficulty, p.TDPresence)
		} else {
			return nil, errHistory
		}
		// Exact ordinary V1 block RPC treatment, independently of participant
		// count: no bloom/gas/blob/size clue about hidden transaction volume.
		block["logsBloom"] = "0x" + strings.Repeat("0", 512)
		block["gasUsed"] = "0x0"
		if _, ok := block["blobGasUsed"]; ok {
			block["blobGasUsed"] = "0x0"
		}
		if _, ok := block["size"]; ok {
			block["size"] = "0x0"
		}
		entries := []any{}
		for _, t := range txs {
			if !r.admit(t.Transaction, readprivacy.TxSurfaceBlockEntry, 0) {
				continue
			}
			if q.FullTransactions() {
				entry, e := historyRPCTransaction(t)
				if e != nil {
					return nil, e
				}
				entries = append(entries, entry)
			} else {
				entries = append(entries, t.Transaction.Hash().Hex())
			}
		}
		block["transactions"] = entries
		value = block
	case rpcexecution.HistoryBlockCountByHash, rpcexecution.HistoryBlockCountByNumber:
		n := 0
		for _, t := range txs {
			if r.admit(t.Transaction, readprivacy.TxSurfaceBlockEntry, 0) {
				n++
			}
		}
		value = fmt.Sprintf("0x%x", n)
	case rpcexecution.HistoryBlockReceipts:
		if len(txs) != len(receipts) {
			return nil, errHistory
		}
		entries := []any{}
		for i, t := range txs {
			if !r.admit(t.Transaction, readprivacy.TxSurfaceBlockEntry, 0) {
				continue
			}
			entry, e := r.receipt(t, receipts[i], readprivacy.TxSurfaceBlockEntry)
			if e != nil {
				return nil, e
			}
			if entry != nil {
				entries = append(entries, entry)
			}
		}
		value = entries
	case rpcexecution.HistoryLogs:
		parents := map[common.Hash]rpcexecution.HistoryTransaction{}
		for _, t := range txs {
			parents[t.Transaction.Hash()] = t.Transaction
		}
		entries := []any{}
		for _, log := range o.Logs() {
			t, ok := parents[log.TransactionHash]
			if !ok {
				return nil, errHistory
			}
			entry, e := r.log(log, t)
			if e != nil {
				return nil, e
			}
			if entry != nil {
				entries = append(entries, entry)
			}
		}
		value = entries
	default:
		return nil, errHistory
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
func historyOptionalBlockFields(out map[string]any, size uint64, sp rpcexecution.HistoryFieldPresence, td *big.Int, tp rpcexecution.HistoryFieldPresence) {
	if sp == rpcexecution.HistoryNull {
		out["size"] = nil
	} else if sp == rpcexecution.HistoryPresent {
		out["size"] = fmt.Sprintf("0x%x", size)
	}
	if tp == rpcexecution.HistoryNull {
		out["totalDifficulty"] = nil
	} else if tp == rpcexecution.HistoryPresent {
		out["totalDifficulty"] = historyQuantity(td)
	}
}
func historyQuantity(n *big.Int) string {
	if n == nil {
		return "0x0"
	}
	return "0x" + n.Text(16)
}
func historyLocationFields(out map[string]any, l rpcexecution.HistoryLocation) {
	out["blockHash"], out["blockNumber"], out["transactionIndex"] = nil, nil, nil
	if l.HashPresent {
		out["blockHash"] = l.BlockHash.Hex()
	}
	if l.NumberPresent {
		out["blockNumber"] = fmt.Sprintf("0x%x", l.BlockNumber)
	}
	if l.IndexPresent {
		out["transactionIndex"] = fmt.Sprintf("0x%x", l.TransactionIndex)
	}
}
func historyRPCTransaction(t rpcexecution.LocatedHistoryTransaction) (map[string]any, error) {
	raw, err := t.Transaction.SignedFieldsJSON()
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil, errHistory
	}
	out["from"] = t.Transaction.From().Hex()
	out["gasPrice"] = historyQuantity(t.GasPrice)
	if fees := t.Transaction.Fees(); !fees.Protected && fees.ChainID.Sign() == 0 {
		delete(out, "chainId")
	}
	historyLocationFields(out, t.Location)
	return out, nil
}
func (r *historyRender) receipt(t rpcexecution.LocatedHistoryTransaction, located rpcexecution.LocatedHistoryReceipt, surface readprivacy.TxSurface) (map[string]any, error) {
	if t.Transaction.Hash() != located.TransactionHash || t.Location != located.Location {
		return nil, errHistory
	}
	// A block entry/strict/deployment without an independent admission path
	// cannot become entitled via a sibling log and need not parse those logs.
	if !r.admit(t.Transaction, surface, int(^uint(0)>>1)) {
		return nil, nil
	}
	receipt := located.Receipt
	logs := []any{}
	for _, log := range receipt.Logs() {
		entry, err := r.log(rpcexecution.LocatedHistoryLog{Log: log, TransactionHash: located.TransactionHash, Location: located.Location}, t.Transaction)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			logs = append(logs, entry)
		}
	}
	if !r.admit(t.Transaction, surface, len(logs)) {
		return nil, nil
	}
	out := map[string]any{"transactionHash": located.TransactionHash.Hex(), "from": t.Transaction.From().Hex(), "to": nil, "type": fmt.Sprintf("0x%x", t.Transaction.Type()), "contractAddress": nil, "gasUsed": fmt.Sprintf("0x%x", receipt.GasUsed()), "cumulativeGasUsed": fmt.Sprintf("0x%x", receipt.CumulativeGasUsed()), "effectiveGasPrice": historyQuantity(receipt.EffectiveGasPrice()), "logsBloom": "0x" + strings.Repeat("0", 512), "logs": logs}
	if to, ok := t.Transaction.To(); ok {
		out["to"] = to.Hex()
	}
	if contract, ok := receipt.ContractAddress(); ok {
		out["contractAddress"] = contract.Hex()
	}
	if status, ok := receipt.Status(); ok {
		out["status"] = fmt.Sprintf("0x%x", status)
	}
	if root, ok := receipt.PostStateRoot(); ok {
		out["root"] = root.Hex()
	}
	if gas, price, ok := receipt.BlobGas(); ok {
		out["blobGasUsed"], out["blobGasPrice"] = fmt.Sprintf("0x%x", gas), historyQuantity(price)
	}
	historyLocationFields(out, located.Location)
	return out, nil
}
func (r *historyRender) log(located rpcexecution.LocatedHistoryLog, t rpcexecution.HistoryTransaction) (map[string]any, error) {
	if r.current == nil {
		return nil, nil
	}
	if r.matcher == nil {
		return nil, errHistory
	}
	log := located.Log
	e, known := r.emitters[log.Address]
	if !known {
		if len(r.emitters) >= 128 {
			return nil, errHistory
		}
		if err := r.matcher.ReserveMetadata(r.current.EmitterMetadataCharge(log.Address) + 128); err != nil {
			return nil, err
		}
		e.metadata = r.current.Emitter(log.Address)
		var err error
		e.layouts, err = r.matcher.Prepare(e.metadata.Registry.ABI)
		if err != nil {
			return nil, err
		}
		r.emitters[log.Address] = e
	}
	topics := make([]string, len(log.Topics))
	pointers := make([]*string, len(log.Topics))
	for i, topic := range log.Topics {
		topics[i] = strings.ToLower(topic.Hex())
		pointers[i] = &topics[i]
	}
	data := "0x" + common.Bytes2Hex(log.Data)
	// This guard precedes every admin/wildcard/unlock/entitled-log path. All
	// downstream helpers see only the ONE actual matched supported event ABI.
	matched, ok, err := r.matcher.MatchPrepared(e.layouts, topics, data)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	facts := readprivacy.LogEmitterFacts{IsAdmin: e.metadata.Admin, Unlocked: e.metadata.VisibleToUnlock && r.listed(located.TransactionHash), HasGrant: e.metadata.HasGrant, ABIResolvable: true, IsParticipant: r.participant(t), InVisibleTo: r.listed(located.TransactionHash), HasTopic0: len(topics) > 0}
	if len(topics) > 0 {
		facts.DynamicPayloadDropped = !e.metadata.Registry.EventsAllowDynamicPayload && readprivacyabi.EventHasDynamicNonIndexedParamJSON(matched, topics[0])
	}
	if rules := e.metadata.Rules; rules != nil {
		if rules.Wildcard {
			facts.Rules = readprivacy.LogEventRulesWildcard
		} else if len(rules.Rules) > 0 {
			facts.Rules = readprivacy.LogEventRulesAllowlist
			for _, rule := range rules.Rules {
				if len(topics) == 0 || !strings.EqualFold(rule.Topic0, topics[0]) {
					continue
				}
				facts.Topic0Allowlisted = true
				if len(rule.ParamRules) == 0 || readprivacyabi.MatchesEventParamRules(readprivacyabi.EventLogInputs{ContractAddress: log.Address.Hex(), Topics: topics, Data: data}, rule.ParamRules, r.own, string(matched)) {
					facts.EventAllowed = true
				}
			}
		}
	}
	if r.profile.Strict() {
		facts.IndexedSelf = r.self.Match(string(matched), topics, data, r.own)
	}
	decision := readprivacy.DecideLogEmitter(r.profile, facts)
	if !decision.Admit {
		return nil, nil
	}
	if decision.Payload != readprivacy.LogPayloadFull {
		visibility := explorerdata.VisibilityMap{}
		var topic0 *string
		if len(pointers) > 0 {
			topic0 = pointers[0]
		}
		for _, address := range readprivacyabi.ExtractLogAddresses(pointers, data, matched, topic0) {
			visibility[strings.ToLower(address)] = r.current.Address(common.HexToAddress(address)).Level
		}
		masked, redacted := readprivacyabi.RedactLogAddressFields(pointers, data, matched, topic0, visibility)
		for i, v := range masked {
			if v != nil {
				topics[i] = *v
			} else {
				topics[i] = ""
			}
		}
		data = redacted
	}
	out := map[string]any{"address": log.Address.Hex(), "topics": topics, "data": data, "transactionHash": located.TransactionHash.Hex(), "logIndex": fmt.Sprintf("0x%x", log.LogIndex), "removed": located.Removed}
	historyLocationFields(out, located.Location)
	return out, nil
}
