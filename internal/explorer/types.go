package explorer

import (
	"encoding/json"
	"time"
)

type JSONString string

func (s JSONString) MarshalJSON() ([]byte, error) {
	return []byte(`"` + string(s) + `"`), nil
}

type Block struct {
	Number           uint64    `json:"number"`
	Hash             string    `json:"hash"`
	ParentHash       string    `json:"parentHash"`
	Timestamp        uint64    `json:"timestamp"`
	GasUsed          uint64    `json:"gasUsed"`
	GasLimit         uint64    `json:"gasLimit"`
	BaseFeePerGas    *uint64   `json:"baseFeePerGas,omitempty"`
	TransactionCount int       `json:"transactionCount"`
	// Size (block serialized byte-length) is a per-block aggregate over every
	// tx — including ones hidden from the viewer — so it leaks other-org block
	// activity/volume. Never serialized to the explorer API (RD-1052); the DB
	// scan / gRPC mapper still populate the struct field for internal use.
	Size             uint64    `json:"-"`
	Difficulty       string    `json:"difficulty"`
	TotalDifficulty  string    `json:"totalDifficulty"`
	Nonce            string    `json:"nonce"`
	Miner            string    `json:"miner"`
	ExtraData        string    `json:"extraData"`
	StateRoot        string    `json:"stateRoot"`
	TransactionsRoot string    `json:"transactionsRoot"`
	ReceiptsRoot     string    `json:"receiptsRoot"`
	CreatedAt        time.Time `json:"createdAt"`
}

type Transaction struct {
	Hash                 string     `json:"hash"`
	BlockNumber          uint64     `json:"blockNumber"`
	BlockTimestamp       uint64     `json:"blockTimestamp,omitempty"`
	TxIndex              int        `json:"txIndex"`
	From                 string     `json:"from"`
	To                   *string    `json:"to"`
	ContractAddress      *string    `json:"contractAddress,omitempty"`
	Value                JSONString `json:"value"`
	GasUsed              uint64     `json:"gasUsed"`
	GasPrice             uint64     `json:"gasPrice"`
	GasLimit             *uint64    `json:"gasLimit,omitempty"`
	MaxFeePerGas         *uint64    `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *uint64    `json:"maxPriorityFeePerGas,omitempty"`
	Nonce                *uint64    `json:"nonce,omitempty"`
	TxType               int        `json:"txType"`
	InputData            string     `json:"inputData"`
	Status               int        `json:"status"`
	Error                *string    `json:"error,omitempty"`
	RevertReason         *string    `json:"revertReason,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
	TxCategories         []string                    `json:"txCategories,omitempty"`
	TokenTransferCount   int                         `json:"tokenTransferCount,omitempty"`
	AddressMetadata      map[string]VisibilityReason `json:"addressMetadata,omitempty"`
}

// IsContractCreation returns true if this transaction is a contract deployment
// (no "to" address — the transaction creates a new contract).
func (tx *Transaction) IsContractCreation() bool {
	return tx.To == nil || *tx.To == ""
}

// HasRecipient returns true if the transaction has a non-empty "to" address.
func (tx *Transaction) HasRecipient() bool {
	return tx.To != nil && *tx.To != ""
}

type AddressStats struct {
	Address            string    `json:"address"`
	TxCount            int       `json:"txCount"`
	InternalTxCount    int       `json:"internalTxCount"`
	TokenTransferCount int       `json:"tokenTransferCount"`
	FirstSeen          *uint64   `json:"firstSeen"`
	LastSeen           *uint64   `json:"lastSeen"`
	IsContract         bool      `json:"isContract"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type TokenTransfer struct {
	ID           int64      `json:"id"`
	TxHash       string     `json:"txHash"`
	LogIndex     int        `json:"logIndex"`
	TokenAddress string     `json:"tokenAddress"`
	From         string     `json:"from"`
	To           string     `json:"to"`
	Value        JSONString `json:"value"`
	BlockNumber  uint64     `json:"blockNumber"`
	Timestamp    *uint64    `json:"timestamp,omitempty"`
	TransferType string     `json:"transferType"`
	TokenType    string     `json:"tokenType"`
	TokenID         *string                     `json:"tokenId,omitempty"`
	IsInternal      bool                        `json:"isInternal"`
	AddressMetadata map[string]VisibilityReason `json:"addressMetadata,omitempty"`
}

type InternalTransaction struct {
	ID           int64      `json:"id"`
	TxHash       string     `json:"txHash"`
	BlockNumber  uint64     `json:"blockNumber"`
	TraceAddress string     `json:"traceAddress"`
	From         string     `json:"from"`
	To           *string    `json:"to"`
	Value        JSONString `json:"value"`
	Gas          *uint64    `json:"gas,omitempty"`
	GasUsed      *uint64    `json:"gasUsed,omitempty"`
	Input        *string    `json:"input,omitempty"`
	Output       *string    `json:"output,omitempty"`
	CallType        string                      `json:"callType"`
	Error           *string                     `json:"error,omitempty"`
	Timestamp       *uint64                     `json:"timestamp,omitempty"`
	AddressMetadata map[string]VisibilityReason `json:"addressMetadata,omitempty"`
}

type Log struct {
	ID          int64   `json:"id"`
	TxHash      string  `json:"txHash"`
	LogIndex    int     `json:"logIndex"`
	Address     string  `json:"address"`
	Topic0      *string `json:"topic0"`
	Topic1      *string `json:"topic1"`
	Topic2      *string `json:"topic2"`
	Topic3      *string `json:"topic3"`
	Data        string  `json:"data"`
	BlockNumber uint64  `json:"blockNumber"`
	Timestamp       *uint64                     `json:"timestamp,omitempty"`
	Removed         bool                        `json:"removed"`
	AddressMetadata map[string]VisibilityReason `json:"addressMetadata,omitempty"`
}

type SyncStatus struct {
	LastIndexedBlock uint64    `json:"lastIndexedBlock"`
	IsSyncing        bool      `json:"isSyncing"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ChainStats struct {
	TotalBlocks       int64   `json:"totalBlocks"`
	TotalTransactions int64   `json:"totalTransactions"`
	TotalAddresses    int64   `json:"totalAddresses"`
	TotalTokens       int64   `json:"totalTokens"`
	AvgBlockTime      float64 `json:"avgBlockTime"`
	PrivacyEnabled    bool    `json:"privacyEnabled"`
}

type Token struct {
	Address           string     `json:"address"`
	Symbol            string     `json:"symbol"`
	Name              *string    `json:"name,omitempty"`
	Decimals          int        `json:"decimals"`
	TokenType         string     `json:"tokenType"`
	TotalSupply       *string    `json:"totalSupply,omitempty"`
	HolderCount       int        `json:"holderCount"`
	TransferCount     int        `json:"transferCount"`
	USDPrice          *float64   `json:"usdPrice,omitempty"`
	IconURL           *string    `json:"iconUrl,omitempty"`
	L1Address         *string    `json:"l1Address,omitempty"`
	BlockNumber       uint64     `json:"blockNumber"`
	CreationTx        *string    `json:"creationTx,omitempty"`
	OffChainUpdatedAt *time.Time `json:"offChainUpdatedAt,omitempty"`
	CreatedAt         time.Time  `json:"createdAt"`
}

type TokenHolder struct {
	Address    string     `json:"address"`
	Balance    JSONString `json:"balance"`
	Percentage float64    `json:"percentage"`
	IsContract bool       `json:"isContract"`
}

type Balance struct {
	Address      string     `json:"address"`
	TokenAddress string     `json:"tokenAddress"`
	BlockNumber  uint64     `json:"blockNumber"`
	Balance      JSONString `json:"balance"`
}

type Contract struct {
	Address          string          `json:"address"`
	Bytecode         string          `json:"bytecode"`
	BytecodeHash     *string         `json:"bytecodeHash,omitempty"`
	Creator          string          `json:"creator"`
	CreationTx       string          `json:"creationTx"`
	BlockNumber      uint64          `json:"blockNumber"`
	IsVerified       bool            `json:"isVerified"`
	ContractName     *string         `json:"contractName,omitempty"`
	CompilerVersion  *string         `json:"compilerVersion,omitempty"`
	OptimizationUsed *bool           `json:"optimizationUsed,omitempty"`
	EVMVersion       *string         `json:"evmVersion,omitempty"`
	SourceCode       *string         `json:"sourceCode,omitempty"`
	ABI              json.RawMessage `json:"abi,omitempty"`
	CreatedAt        time.Time       `json:"createdAt"`
	LicenseType      *string         `json:"licenseType,omitempty"`
	ConstructorArgs  *string         `json:"constructorArgs,omitempty"`
	OptimizationRuns *int            `json:"optimizationRuns,omitempty"`
}

type SearchSuggestion struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Label string `json:"label"`
}

type TxHistoryPoint struct {
	Timestamp uint64 `json:"timestamp"`
	Count     int64  `json:"count"`
}

type IndexerProgress struct {
	ID               int       `json:"id"`
	MinFetchedBlock  uint64    `json:"minFetchedBlock"`
	MaxFetchedBlock  uint64    `json:"maxFetchedBlock"`
	BackfillComplete bool      `json:"backfillComplete"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type OPDeposit struct {
	L2TxHash        string    `json:"l2TxHash"`
	L1BlockNumber   uint64    `json:"l1BlockNumber"`
	L1BlockTimestamp *uint64   `json:"l1BlockTimestamp,omitempty"`
	L1TxHash        string    `json:"l1TxHash"`
	L1TxOrigin      string    `json:"l1TxOrigin"`
	CreatedAt       time.Time `json:"createdAt"`
}
