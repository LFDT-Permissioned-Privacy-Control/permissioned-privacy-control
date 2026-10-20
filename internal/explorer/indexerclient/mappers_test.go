package indexerclient

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// These tests exercise the proto -> internal explorer.* mappers in isolation.
// They document the field-level contract consumers rely on.
//
// A full end-to-end parity test (same postgres hit by both *explorer.Store
// and Backend via a real gRPC server) is deferred to the compose-stack e2e
// tier, where chain-indexer and Open Privacy Suite already run alongside each
// other. Exercising the mappers here is enough to catch shape / nil /
// unit regressions; true behavioral parity (pagination, category flags,
// SQL-layer visibility vs post-fetch Go-layer filtering) is a runtime
// concern the e2e tier covers.

func TestMapBlock(t *testing.T) {
	base := uint64(42)
	in := &indexerv1.Block{
		Number:           100,
		Hash:             "0xblock",
		ParentHash:       "0xparent",
		Timestamp:        timestamppb.New(timeOf(1_700_000_000)),
		Miner:            "0xminer",
		GasUsed:          21000,
		GasLimit:         30_000_000,
		BaseFeePerGas:    &indexerv1.BigInt{Value: "42"},
		Difficulty:       &indexerv1.BigInt{Value: "123"},
		TotalDifficulty:  &indexerv1.BigInt{Value: "456"},
		StateRoot:        "0xstate",
		TransactionsRoot: "0xtxroot",
		ReceiptsRoot:     "0xrcptroot",
		ExtraData:        "0xextra",
		Nonce:            "0xnonce",
		Size:             500,
		TransactionCount: 7,
	}
	out := mapBlock(in)
	if out == nil {
		t.Fatal("mapBlock returned nil")
	}
	if out.Number != 100 || out.Hash != "0xblock" || out.GasUsed != 21000 {
		t.Errorf("scalar fields mismatch: %+v", out)
	}
	if out.BaseFeePerGas == nil || *out.BaseFeePerGas != base {
		t.Errorf("base fee mismatch: got %v want %d", out.BaseFeePerGas, base)
	}
	if out.Difficulty != "123" || out.TotalDifficulty != "456" {
		t.Errorf("difficulty fields: %q / %q", out.Difficulty, out.TotalDifficulty)
	}
	if out.TransactionCount != 7 {
		t.Errorf("transaction count: %d", out.TransactionCount)
	}
}

func TestMapBlock_NilBaseFee(t *testing.T) {
	in := &indexerv1.Block{Number: 1, BaseFeePerGas: &indexerv1.BigInt{}}
	out := mapBlock(in)
	if out.BaseFeePerGas != nil {
		t.Errorf("empty BigInt should yield nil BaseFeePerGas, got %v", out.BaseFeePerGas)
	}
}

func TestMapTransaction_ContractCreation(t *testing.T) {
	in := &indexerv1.Transaction{
		Hash:            "0xtx",
		BlockNumber:     1,
		TransactionIndex: 0,
		From:            "0xdeployer",
		To:              "", // empty = contract creation
		Value:           &indexerv1.BigInt{Value: "0"},
		GasUsed:         500000,
		GasPrice:        &indexerv1.BigInt{Value: "1000000000"},
		Status:          indexerv1.TransactionStatus_TRANSACTION_STATUS_SUCCESS,
		ContractAddress: "0xdeployed",
		Categories: []indexerv1.TransactionCategory{
			indexerv1.TransactionCategory_TRANSACTION_CATEGORY_CONTRACT_CREATION,
		},
	}
	out := mapTransaction(in)
	if out.To != nil {
		t.Errorf("To should be nil for contract creation, got %v", out.To)
	}
	if out.ContractAddress == nil || *out.ContractAddress != "0xdeployed" {
		t.Errorf("ContractAddress: %v", out.ContractAddress)
	}
	if out.Status != 1 {
		t.Errorf("Status: %d", out.Status)
	}
	if len(out.TxCategories) != 1 || out.TxCategories[0] != "contract_creation" {
		t.Errorf("categories: %v", out.TxCategories)
	}
}

func TestMapAddressStats(t *testing.T) {
	in := &indexerv1.Address{
		Address:        "0xaddr",
		IsContract:     true,
		TxCountIn:      3,
		TxCountOut:     7,
		TokenCount:     2,
		FirstSeenBlock: 100,
		LastSeenBlock:  200,
	}
	out := mapAddressStats(in)
	if out.Address != "0xaddr" || !out.IsContract || out.TxCount != 10 {
		t.Errorf("basic fields: %+v", out)
	}
	if out.FirstSeen == nil || *out.FirstSeen != 100 {
		t.Errorf("FirstSeen: %v", out.FirstSeen)
	}
	if out.LastSeen == nil || *out.LastSeen != 200 {
		t.Errorf("LastSeen: %v", out.LastSeen)
	}
}

func TestMapChainStats(t *testing.T) {
	in := &indexerv1.ChainStats{
		TotalBlocks:         500,
		TotalTransactions:   1000,
		TotalAddresses:      50,
		AvgBlockTimeSeconds: 12.5,
	}
	out := mapChainStats(in)
	if out.TotalBlocks != 500 || out.TotalTransactions != 1000 || out.TotalAddresses != 50 {
		t.Errorf("counts: %+v", out)
	}
	if out.AvgBlockTime < 12.4 || out.AvgBlockTime > 12.6 {
		t.Errorf("AvgBlockTime: %v", out.AvgBlockTime)
	}
	if !out.PrivacyEnabled {
		t.Error("PrivacyEnabled should be true")
	}
}

func TestMapSyncStatus(t *testing.T) {
	in := &indexerv1.SyncStatus{
		LatestIndexedBlock: 999,
		IsSyncing:          true,
	}
	out := mapSyncStatus(in)
	if out.LastIndexedBlock != 999 || !out.IsSyncing {
		t.Errorf("sync status: %+v", out)
	}
}

// compile-time check that mappers preserve Transaction interface.
var _ = mapTransaction
var _ *explorer.Block = mapBlock(nil)
