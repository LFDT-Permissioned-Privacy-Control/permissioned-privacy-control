package explorer

import "privacy-proxy/internal/explorerdata"

// Legacy names alias the data-only declarations; their JSON behavior is unchanged.
type JSONString = explorerdata.JSONString
type Block = explorerdata.Block
type Transaction = explorerdata.Transaction
type AddressStats = explorerdata.AddressStats
type TokenTransfer = explorerdata.TokenTransfer
type InternalTransaction = explorerdata.InternalTransaction
type Log = explorerdata.Log
type SyncStatus = explorerdata.SyncStatus
type ChainStats = explorerdata.ChainStats
type Token = explorerdata.Token
type TokenHolder = explorerdata.TokenHolder
type Balance = explorerdata.Balance
type Contract = explorerdata.Contract
type SearchSuggestion = explorerdata.SearchSuggestion
type TxHistoryPoint = explorerdata.TxHistoryPoint
type IndexerProgress = explorerdata.IndexerProgress
type OPDeposit = explorerdata.OPDeposit
