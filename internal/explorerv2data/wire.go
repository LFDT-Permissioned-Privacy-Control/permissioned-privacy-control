// Package explorerv2data holds lossless V2 Explorer response values. It owns no
// data acquisition, policy decisions or storage connection.
package explorerv2data

import "encoding/json"

type Quantity string
type Decimal string
type Hex string
type Address = string
type Hash = string
type OpaqueRowID = string
type AddressMetadata = map[string]string

const Population = "LIVE_RETAINED_INDEXED_ROWS_CURRENT_RIGHTS"

type Page[T any] struct {
	Items []T      `json:"items"`
	Page  PageInfo `json:"page"`
}

type PageInfo struct {
	Next        *string   `json:"next,omitempty"`
	HasMore     *bool     `json:"hasMore"`
	ScanLimited bool      `json:"scanLimited"`
	Total       *Quantity `json:"total,omitempty"`
	Population  string    `json:"population"`
}

type Block struct {
	Number           Quantity  `json:"number"`
	Hash             Hash      `json:"hash"`
	ParentHash       Hash      `json:"parentHash"`
	Timestamp        Quantity  `json:"timestamp"`
	GasLimit         Quantity  `json:"gasLimit"`
	BaseFeePerGas    *Quantity `json:"baseFeePerGas,omitempty"`
	TransactionCount *Quantity `json:"transactionCount,omitempty"`
	Difficulty       Quantity  `json:"difficulty"`
	TotalDifficulty  *Quantity `json:"totalDifficulty,omitempty"`
	Nonce            Hex       `json:"nonce"`
	Miner            Address   `json:"miner"`
	ExtraData        Hex       `json:"extraData"`
	StateRoot        Hash      `json:"stateRoot"`
	TransactionsRoot Hash      `json:"transactionsRoot"`
	ReceiptsRoot     Hash      `json:"receiptsRoot"`
	CreatedAt        string    `json:"createdAt"`
}

type Transaction struct {
	Hash                 Hash             `json:"hash"`
	BlockNumber          *Quantity        `json:"blockNumber"`
	BlockTimestamp       *Quantity        `json:"blockTimestamp,omitempty"`
	TxIndex              *uint32          `json:"txIndex"`
	From                 Address          `json:"from"`
	To                   *Address         `json:"to"`
	ContractAddress      *Address         `json:"contractAddress,omitempty"`
	Value                *Quantity        `json:"value"`
	GasUsed              *Quantity        `json:"gasUsed,omitempty"`
	GasPrice             Quantity         `json:"gasPrice"`
	GasLimit             *Quantity        `json:"gasLimit,omitempty"`
	MaxFeePerGas         *Quantity        `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *Quantity        `json:"maxPriorityFeePerGas,omitempty"`
	Nonce                *Quantity        `json:"nonce,omitempty"`
	MaxFeePerBlobGas     *Quantity        `json:"maxFeePerBlobGas,omitempty"`
	TxType               uint8            `json:"txType"`
	InputData            Hex              `json:"inputData"`
	Status               *uint8           `json:"status"`
	PostStateRoot        *Hash            `json:"postStateRoot,omitempty"`
	Error                *string          `json:"error,omitempty"`
	RevertReason         *string          `json:"revertReason,omitempty"`
	CreatedAt            *string          `json:"createdAt,omitempty"`
	TxCategories         *[]string        `json:"txCategories,omitempty"`
	TokenTransferCount   *Quantity        `json:"tokenTransferCount,omitempty"`
	AddressMetadata      *AddressMetadata `json:"addressMetadata,omitempty"`
}

type TokenTransfer struct {
	ID              OpaqueRowID      `json:"id"`
	TxHash          Hash             `json:"txHash"`
	LogIndex        uint32           `json:"logIndex"`
	TokenAddress    Address          `json:"tokenAddress"`
	From            Address          `json:"from"`
	To              Address          `json:"to"`
	Value           *Quantity        `json:"value"`
	BlockNumber     Quantity         `json:"blockNumber"`
	Timestamp       *Quantity        `json:"timestamp,omitempty"`
	TransferType    string           `json:"transferType"`
	TokenType       string           `json:"tokenType"`
	TokenID         *Quantity        `json:"tokenId,omitempty"`
	IsInternal      bool             `json:"isInternal"`
	AddressMetadata *AddressMetadata `json:"addressMetadata,omitempty"`
}

type InternalTransaction struct {
	ID              OpaqueRowID      `json:"id"`
	TxHash          Hash             `json:"txHash"`
	BlockNumber     Quantity         `json:"blockNumber"`
	TraceAddress    string           `json:"traceAddress"`
	From            Address          `json:"from"`
	To              *Address         `json:"to"`
	Value           *Quantity        `json:"value"`
	Gas             *Quantity        `json:"gas,omitempty"`
	GasUsed         *Quantity        `json:"gasUsed,omitempty"`
	Input           *Hex             `json:"input,omitempty"`
	Output          *Hex             `json:"output,omitempty"`
	CallType        string           `json:"callType"`
	Error           *string          `json:"error,omitempty"`
	Timestamp       *Quantity        `json:"timestamp,omitempty"`
	AddressMetadata *AddressMetadata `json:"addressMetadata,omitempty"`
}

type Log struct {
	ID              OpaqueRowID      `json:"id"`
	TxHash          Hash             `json:"txHash"`
	LogIndex        uint32           `json:"logIndex"`
	Address         Address          `json:"address"`
	Topic0          *Hash            `json:"topic0"`
	Topic1          *Hash            `json:"topic1"`
	Topic2          *Hash            `json:"topic2"`
	Topic3          *Hash            `json:"topic3"`
	Data            Hex              `json:"data"`
	BlockNumber     Quantity         `json:"blockNumber"`
	Timestamp       *Quantity        `json:"timestamp,omitempty"`
	Removed         bool             `json:"removed"`
	AddressMetadata *AddressMetadata `json:"addressMetadata,omitempty"`
}

type Token struct {
	Address           Address   `json:"address"`
	Symbol            string    `json:"symbol"`
	Name              *string   `json:"name,omitempty"`
	Decimals          uint32    `json:"decimals"`
	TokenType         string    `json:"tokenType"`
	TotalSupply       *Quantity `json:"totalSupply,omitempty"`
	HolderCount       *Quantity `json:"holderCount,omitempty"`
	TransferCount     *Quantity `json:"transferCount,omitempty"`
	USDPrice          *Decimal  `json:"usdPrice,omitempty"`
	IconURL           *string   `json:"iconUrl,omitempty"`
	L1Address         *Address  `json:"l1Address,omitempty"`
	BlockNumber       Quantity  `json:"blockNumber"`
	CreationTx        *Hash     `json:"creationTx,omitempty"`
	OffChainUpdatedAt *string   `json:"offChainUpdatedAt,omitempty"`
	CreatedAt         string    `json:"createdAt"`
}

type TokenHolder struct {
	Address    Address  `json:"address"`
	Balance    Quantity `json:"balance"`
	Percentage *Decimal `json:"percentage,omitempty"`
	IsContract *bool    `json:"isContract,omitempty"`
}

type Balance struct {
	Address      Address  `json:"address"`
	TokenAddress Address  `json:"tokenAddress"`
	BlockNumber  Quantity `json:"blockNumber"`
	Balance      Quantity `json:"balance"`
}

type AddressStats struct {
	Address            Address   `json:"address"`
	TxCount            *Quantity `json:"txCount,omitempty"`
	InternalTxCount    *Quantity `json:"internalTxCount,omitempty"`
	TokenTransferCount *Quantity `json:"tokenTransferCount,omitempty"`
	FirstSeen          *Quantity `json:"firstSeen,omitempty"`
	LastSeen           *Quantity `json:"lastSeen,omitempty"`
	IsContract         *bool     `json:"isContract,omitempty"`
	UpdatedAt          *string   `json:"updatedAt,omitempty"`
}

type ChainStats struct {
	TotalBlocks       *Quantity `json:"totalBlocks,omitempty"`
	TotalTransactions *Quantity `json:"totalTransactions,omitempty"`
	TotalAddresses    *Quantity `json:"totalAddresses,omitempty"`
	TotalTokens       *Quantity `json:"totalTokens,omitempty"`
	AvgBlockTime      *Decimal  `json:"avgBlockTime,omitempty"`
	PrivacyEnabled    bool      `json:"privacyEnabled"`
}

type TxHistoryPoint struct {
	Timestamp Quantity `json:"timestamp"`
}

type Contract struct {
	Address          Address            `json:"address"`
	Bytecode         *Hex               `json:"bytecode,omitempty"`
	BytecodeHash     *Hash              `json:"bytecodeHash,omitempty"`
	Creator          *Address           `json:"creator,omitempty"`
	CreationTx       *Hash              `json:"creationTx,omitempty"`
	BlockNumber      *Quantity          `json:"blockNumber,omitempty"`
	IsVerified       *bool              `json:"isVerified,omitempty"`
	ContractName     *string            `json:"contractName,omitempty"`
	CompilerVersion  *string            `json:"compilerVersion,omitempty"`
	OptimizationUsed *bool              `json:"optimizationUsed,omitempty"`
	EvmVersion       *string            `json:"evmVersion,omitempty"`
	SourceCode       *string            `json:"sourceCode,omitempty"`
	ABI              *[]json.RawMessage `json:"abi,omitempty"`
	CreatedAt        *string            `json:"createdAt,omitempty"`
	LicenseType      *string            `json:"licenseType,omitempty"`
	ConstructorArgs  *Hex               `json:"constructorArgs,omitempty"`
	OptimizationRuns *uint32            `json:"optimizationRuns,omitempty"`
}

type SearchSuggestion struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SyncStatus struct {
	LastIndexedBlock Quantity `json:"lastIndexedBlock"`
	IsSyncing        bool     `json:"isSyncing"`
	UpdatedAt        string   `json:"updatedAt"`
}

type IndexerProgress struct {
	MinFetchedBlock  Quantity `json:"minFetchedBlock"`
	MaxFetchedBlock  Quantity `json:"maxFetchedBlock"`
	BackfillComplete bool     `json:"backfillComplete"`
	UpdatedAt        string   `json:"updatedAt"`
}

type Catchup struct {
	Indexer IndexerProgress `json:"indexer"`
	Sync    SyncStatus      `json:"sync"`
}

type ChainID struct {
	ChainID Quantity `json:"chainId"`
}

type LatestBlock struct {
	Number Quantity `json:"number"`
}

type NativeBalance struct {
	Address     Address   `json:"address"`
	Balance     Quantity  `json:"balance"`
	BlockNumber *Quantity `json:"blockNumber,omitempty"`
}

type Code struct {
	Address     Address   `json:"address"`
	Code        Hex       `json:"code"`
	BlockNumber *Quantity `json:"blockNumber,omitempty"`
}

type IsContract struct {
	IsContract bool    `json:"isContract"`
	Address    Address `json:"address"`
}
