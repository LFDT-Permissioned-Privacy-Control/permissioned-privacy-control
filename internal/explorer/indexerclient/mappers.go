package indexerclient

import (
	"strconv"

	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// Type conversion helpers from chain-indexer proto messages to Open Privacy Suite's
// internal explorer.* types. Kept narrow and field-by-field so breakage is
// explicit when the proto changes.

func unixSec(t interface{ GetSeconds() int64 }) uint64 {
	if t == nil {
		return 0
	}
	s := t.GetSeconds()
	if s < 0 {
		return 0
	}
	return uint64(s)
}

// big converts a proto BigInt to a string ("" if unset or zero-value).
func big(b *indexerv1.BigInt) string {
	if b == nil {
		return ""
	}
	return b.GetValue()
}

// bigToUint64Ptr parses a decimal BigInt into *uint64. Returns nil if empty
// or unparseable. Used for fields that the Open Privacy Suite store historically
// scanned as *uint64 directly from postgres.
func bigToUint64Ptr(b *indexerv1.BigInt) *uint64 {
	if b == nil || b.GetValue() == "" {
		return nil
	}
	n, err := strconv.ParseUint(b.GetValue(), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func bigToUint64(b *indexerv1.BigInt) uint64 {
	if b == nil || b.GetValue() == "" {
		return 0
	}
	n, err := strconv.ParseUint(b.GetValue(), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func mapBlock(b *indexerv1.Block) *explorer.Block {
	if b == nil {
		return nil
	}
	baseFee := bigToUint64Ptr(b.GetBaseFeePerGas())
	return &explorer.Block{
		Number:           b.GetNumber(),
		Hash:             b.GetHash(),
		ParentHash:       b.GetParentHash(),
		Timestamp:        unixSec(b.GetTimestamp()),
		GasUsed:          b.GetGasUsed(),
		GasLimit:         b.GetGasLimit(),
		BaseFeePerGas:    baseFee,
		TransactionCount: int(b.GetTransactionCount()),
		Size:             b.GetSize(),
		Difficulty:       big(b.GetDifficulty()),
		TotalDifficulty:  big(b.GetTotalDifficulty()),
		Nonce:            b.GetNonce(),
		Miner:            b.GetMiner(),
		ExtraData:        b.GetExtraData(),
		StateRoot:        b.GetStateRoot(),
		TransactionsRoot: b.GetTransactionsRoot(),
		ReceiptsRoot:     b.GetReceiptsRoot(),
		// CreatedAt is a DB-local timestamp, not carried over gRPC.
	}
}

// mapCategory translates a proto TransactionCategory enum to the string label
// that Open Privacy Suite's existing code (and tests) expects.
func mapCategory(c indexerv1.TransactionCategory) string {
	switch c {
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_COIN_TRANSFER:
		return "coin_transfer"
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_CONTRACT_CREATION:
		return "contract_creation"
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_CONTRACT_CALL:
		return "contract_call"
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_TOKEN_TRANSFER:
		return "token_transfer"
	}
	return ""
}

func mapCategories(cs []indexerv1.TransactionCategory) []string {
	if len(cs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		if label := mapCategory(c); label != "" {
			out = append(out, label)
		}
	}
	return out
}

func mapStatus(s indexerv1.TransactionStatus) int {
	switch s {
	case indexerv1.TransactionStatus_TRANSACTION_STATUS_SUCCESS:
		return 1
	case indexerv1.TransactionStatus_TRANSACTION_STATUS_FAILED:
		return 0
	}
	return 0
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func mapTransaction(t *indexerv1.Transaction) *explorer.Transaction {
	if t == nil {
		return nil
	}
	var to *string
	if t.GetTo() != "" {
		to = stringPtr(t.GetTo())
	}
	var contractAddr *string
	if t.GetContractAddress() != "" {
		contractAddr = stringPtr(t.GetContractAddress())
	}
	gasLimit := t.GetGas()
	nonce := t.GetNonce()
	return &explorer.Transaction{
		Hash:                 t.GetHash(),
		BlockNumber:          t.GetBlockNumber(),
		BlockTimestamp:       unixSec(t.GetBlockTimestamp()),
		TxIndex:              int(t.GetTransactionIndex()),
		From:                 t.GetFrom(),
		To:                   to,
		ContractAddress:      contractAddr,
		Value:                explorer.JSONString(big(t.GetValue())),
		GasUsed:              t.GetGasUsed(),
		GasPrice:             bigToUint64(t.GetGasPrice()),
		GasLimit:             &gasLimit,
		MaxFeePerGas:         bigToUint64Ptr(t.GetMaxFeePerGas()),
		MaxPriorityFeePerGas: bigToUint64Ptr(t.GetMaxPriorityFeePerGas()),
		Nonce:                &nonce,
		TxType:               int(t.GetTxType()),
		InputData:            t.GetInput(),
		Status:               mapStatus(t.GetStatus()),
		TxCategories:         mapCategories(t.GetCategories()),
	}
}

func mapAddressStats(a *indexerv1.Address) *explorer.AddressStats {
	if a == nil {
		return nil
	}
	first := a.GetFirstSeenBlock()
	last := a.GetLastSeenBlock()
	return &explorer.AddressStats{
		Address:            a.GetAddress(),
		TxCount:            int(a.GetTxCountIn() + a.GetTxCountOut()),
		InternalTxCount:    0, // chain-indexer collapses this into proto Address.TxCount*; not exposed separately
		TokenTransferCount: int(a.GetTokenCount()),
		FirstSeen:          &first,
		LastSeen:           &last,
		IsContract:         a.GetIsContract(),
	}
}

func mapChainStats(c *indexerv1.ChainStats) *explorer.ChainStats {
	if c == nil {
		return nil
	}
	return &explorer.ChainStats{
		TotalBlocks:       int64(c.GetTotalBlocks()),
		TotalTransactions: int64(c.GetTotalTransactions()),
		TotalAddresses:    int64(c.GetTotalAddresses()),
		TotalTokens:       0, // not exposed separately by the indexer today
		AvgBlockTime:      float64(c.GetAvgBlockTimeSeconds()),
		PrivacyEnabled:    true,
	}
}

func mapSyncStatus(s *indexerv1.SyncStatus) *explorer.SyncStatus {
	if s == nil {
		return nil
	}
	return &explorer.SyncStatus{
		LastIndexedBlock: s.GetLatestIndexedBlock(),
		IsSyncing:        s.GetIsSyncing(),
	}
}

// ----- Stage 2 mappers -----

func mapBlocks(in []*indexerv1.Block) []explorer.Block {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.Block, 0, len(in))
	for _, b := range in {
		if b == nil {
			continue
		}
		out = append(out, *mapBlock(b))
	}
	return out
}

func mapTransactions(in []*indexerv1.Transaction) []explorer.Transaction {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.Transaction, 0, len(in))
	for _, t := range in {
		if t == nil {
			continue
		}
		out = append(out, *mapTransaction(t))
	}
	return out
}

// mapLog converts one proto Log. The proto uses a single `topics[]` list;
// the explorer type splits them across Topic0..Topic3.
func mapLog(l *indexerv1.Log) explorer.Log {
	out := explorer.Log{
		TxHash:      l.GetTransactionHash(),
		LogIndex:    int(l.GetLogIndex()),
		Address:     l.GetAddress(),
		Data:        l.GetData(),
		BlockNumber: l.GetBlockNumber(),
		Removed:     l.GetRemoved(),
	}
	if ts := l.GetBlockTimestamp(); ts != nil {
		u := unixSec(ts)
		out.Timestamp = &u
	}
	topics := l.GetTopics()
	if len(topics) > 0 {
		t := topics[0]
		out.Topic0 = &t
	}
	if len(topics) > 1 {
		t := topics[1]
		out.Topic1 = &t
	}
	if len(topics) > 2 {
		t := topics[2]
		out.Topic2 = &t
	}
	if len(topics) > 3 {
		t := topics[3]
		out.Topic3 = &t
	}
	return out
}

func mapLogs(in []*indexerv1.Log) []explorer.Log {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.Log, 0, len(in))
	for _, l := range in {
		if l == nil {
			continue
		}
		out = append(out, mapLog(l))
	}
	return out
}

// mapTokenType translates the proto enum into the string label the explorer
// package uses in its JSON.
func mapTokenType(t indexerv1.TokenType) string {
	switch t {
	case indexerv1.TokenType_TOKEN_TYPE_ERC20:
		return "ERC20"
	case indexerv1.TokenType_TOKEN_TYPE_ERC721:
		return "ERC721"
	case indexerv1.TokenType_TOKEN_TYPE_ERC1155:
		return "ERC1155"
	}
	return ""
}

func mapToken(t *indexerv1.Token) *explorer.Token {
	if t == nil {
		return nil
	}
	var name *string
	if n := t.GetName(); n != "" {
		name = &n
	}
	var totalSupply *string
	if s := big(t.GetTotalSupply()); s != "" {
		totalSupply = &s
	}
	var iconURL *string
	if u := t.GetIconUrl(); u != "" {
		iconURL = &u
	}
	var usdPrice *float64
	if p := t.GetPriceUsd(); p != "" {
		if v, err := strconv.ParseFloat(p, 64); err == nil {
			usdPrice = &v
		}
	}
	return &explorer.Token{
		Address:       t.GetAddress(),
		Symbol:        t.GetSymbol(),
		Name:          name,
		Decimals:      int(t.GetDecimals()),
		TokenType:     mapTokenType(t.GetTokenType()),
		TotalSupply:   totalSupply,
		HolderCount:   int(t.GetHolderCount()),
		TransferCount: int(t.GetTransferCount()),
		USDPrice:      usdPrice,
		IconURL:       iconURL,
	}
}

func mapTokens(in []*indexerv1.Token) []explorer.Token {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.Token, 0, len(in))
	for _, t := range in {
		if t == nil {
			continue
		}
		out = append(out, *mapToken(t))
	}
	return out
}

func mapTokenTransfer(t *indexerv1.TokenTransfer) explorer.TokenTransfer {
	out := explorer.TokenTransfer{
		TxHash:       t.GetTransactionHash(),
		LogIndex:     int(t.GetLogIndex()),
		TokenAddress: t.GetTokenAddress(),
		From:         t.GetFrom(),
		To:           t.GetTo(),
		Value:        explorer.JSONString(big(t.GetValue())),
		BlockNumber:  t.GetBlockNumber(),
		TokenType:    mapTokenType(t.GetTokenType()),
	}
	if ts := t.GetBlockTimestamp(); ts != nil {
		u := unixSec(ts)
		out.Timestamp = &u
	}
	if id := big(t.GetTokenId()); id != "" {
		out.TokenID = &id
	}
	return out
}

func mapTokenTransfers(in []*indexerv1.TokenTransfer) []explorer.TokenTransfer {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.TokenTransfer, 0, len(in))
	for _, t := range in {
		if t == nil {
			continue
		}
		out = append(out, mapTokenTransfer(t))
	}
	return out
}

func mapTokenHolders(in []*indexerv1.TokenBalance) []explorer.TokenHolder {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.TokenHolder, 0, len(in))
	for _, h := range in {
		if h == nil {
			continue
		}
		out = append(out, explorer.TokenHolder{
			Address: h.GetAddress(),
			Balance: explorer.JSONString(big(h.GetBalance())),
			// Percentage / IsContract not emitted by the indexer today.
		})
	}
	return out
}

func mapBalances(in []*indexerv1.TokenBalance) []explorer.Balance {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.Balance, 0, len(in))
	for _, h := range in {
		if h == nil {
			continue
		}
		out = append(out, explorer.Balance{
			Address:      h.GetAddress(),
			TokenAddress: h.GetTokenAddress(),
			Balance:      explorer.JSONString(big(h.GetBalance())),
		})
	}
	return out
}

func mapInternalTx(it *indexerv1.InternalTransaction) explorer.InternalTransaction {
	out := explorer.InternalTransaction{
		TxHash:       it.GetTransactionHash(),
		BlockNumber:  it.GetBlockNumber(),
		TraceAddress: it.GetTraceAddress(),
		From:         it.GetFrom(),
		Value:        explorer.JSONString(big(it.GetValue())),
		CallType:     it.GetCallType(),
	}
	if to := it.GetTo(); to != "" {
		out.To = &to
	}
	if gas := it.GetGas(); gas != 0 {
		out.Gas = &gas
	}
	if g := it.GetGasUsed(); g != 0 {
		out.GasUsed = &g
	}
	if in := it.GetInput(); in != "" {
		out.Input = &in
	}
	if o := it.GetOutput(); o != "" {
		out.Output = &o
	}
	if e := it.GetError(); e != "" {
		out.Error = &e
	}
	if ts := it.GetBlockTimestamp(); ts != nil {
		u := unixSec(ts)
		out.Timestamp = &u
	}
	return out
}

func mapInternalTxs(in []*indexerv1.InternalTransaction) []explorer.InternalTransaction {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.InternalTransaction, 0, len(in))
	for _, it := range in {
		if it == nil {
			continue
		}
		out = append(out, mapInternalTx(it))
	}
	return out
}

func mapContract(c *indexerv1.Contract) *explorer.Contract {
	if c == nil {
		return nil
	}
	// Indexer returns chain facts only. ABI / source / verification metadata
	// are intentionally not carried over gRPC (RD-855). Consumers that need
	// those fall back to the SQL store path.
	return &explorer.Contract{
		Address:     c.GetAddress(),
		Bytecode:    c.GetBytecode(),
		Creator:     c.GetDeployer(),
		CreationTx:  c.GetDeploymentTxHash(),
		BlockNumber: c.GetDeploymentBlock(),
	}
}

func mapAccounts(in []*indexerv1.Address) []explorer.AddressStats {
	if len(in) == 0 {
		return nil
	}
	out := make([]explorer.AddressStats, 0, len(in))
	for _, a := range in {
		if a == nil {
			continue
		}
		out = append(out, *mapAddressStats(a))
	}
	return out
}

func mapSearchResults(in *indexerv1.SearchResponse) []explorer.SearchSuggestion {
	if in == nil {
		return nil
	}
	results := in.GetResults()
	out := make([]explorer.SearchSuggestion, 0, len(results))
	for _, r := range results {
		sug := explorer.SearchSuggestion{}
		switch r.GetKind() {
		case indexerv1.SearchResponse_SEARCH_RESULT_KIND_BLOCK:
			sug.Type = "block"
			if b := r.GetBlock(); b != nil {
				sug.Value = strconv.FormatUint(b.GetNumber(), 10)
				sug.Label = "Block #" + sug.Value
			}
		case indexerv1.SearchResponse_SEARCH_RESULT_KIND_TRANSACTION:
			sug.Type = "transaction"
			if t := r.GetTransaction(); t != nil {
				sug.Value = t.GetHash()
				sug.Label = truncateHash(sug.Value)
			}
		case indexerv1.SearchResponse_SEARCH_RESULT_KIND_ADDRESS:
			sug.Type = "address"
			if a := r.GetAddress(); a != nil {
				sug.Value = a.GetAddress()
				sug.Label = truncateHash(sug.Value)
			}
		case indexerv1.SearchResponse_SEARCH_RESULT_KIND_TOKEN:
			sug.Type = "token"
			if t := r.GetToken(); t != nil {
				sug.Value = t.GetAddress()
				sug.Label = t.GetSymbol()
			}
		default:
			continue
		}
		out = append(out, sug)
	}
	return out
}

func truncateHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "..." + h[len(h)-6:]
}

func mapTxHistory(in *indexerv1.TransactionHistory) []explorer.TxHistoryPoint {
	if in == nil {
		return nil
	}
	buckets := in.GetBuckets()
	out := make([]explorer.TxHistoryPoint, 0, len(buckets))
	for _, b := range buckets {
		if b == nil {
			continue
		}
		out = append(out, explorer.TxHistoryPoint{
			Timestamp: unixSec(b.GetBucketStart()),
			Count:     int64(b.GetTransactionCount()),
		})
	}
	return out
}
