package explorerindex

import (
	"encoding/json"
	"fmt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"math/big"
	pb "privacy-proxy/gen/go/chain_indexer/v2"
	q "privacy-proxy/internal/explorerquery"
	"strconv"
	"time"
)

func decimal(n uint64) string { return strconv.FormatUint(n, 10) }
func stamp(t *timestamppb.Timestamp) any {
	if t == nil {
		return nil
	}
	if t.CheckValid() != nil {
		return nil
	}
	return t.AsTime().UTC().Format(time.RFC3339Nano)
}
func nullableHex(b []byte) any {
	if b == nil {
		return nil
	}
	return hexBytes(b)
}
func quantity(s string) bool {
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() >= 0 && n.BitLen() <= 256 && n.String() == s
}
func hash(b []byte) bool    { return len(b) == 32 }
func address(b []byte) bool { return len(b) == 20 }
func keyWire(f q.Family, p *q.Position) (*pb.Key, error) {
	if p == nil {
		return nil, nil
	}
	k := &pb.Key{}
	b := func(s string, n int) []byte { v, _ := unhex(s, n); return v }
	switch f {
	case q.Blocks:
		k.Value = &pb.Key_Block{Block: &pb.BlockKey{Number: p.Block}}
	case q.Transactions:
		k.Value = &pb.Key_Transaction{Transaction: &pb.TransactionKey{BlockNumber: p.Block, TransactionIndex: p.Index, Hash: b(p.Hash, 32)}}
	case q.Logs:
		k.Value = &pb.Key_Log{Log: &pb.LogKey{BlockNumber: p.Block, LogIndex: p.Index}}
	case q.Transfers:
		k.Value = &pb.Key_Transfer{Transfer: &pb.TransferKey{BlockNumber: p.Block, LogIndex: p.Index}}
	case q.Internals:
		k.Value = &pb.Key_Internal{Internal: &pb.InternalKey{BlockNumber: p.Block, TransactionHash: b(p.Hash, 32), TraceAddress: p.Subkey}}
	case q.Contracts, q.Tokens:
		k.Value = &pb.Key_Creation{Creation: &pb.CreationKey{BlockNumber: p.Block, Address: b(p.Hash, 20)}}
	case q.Addresses:
		k.Value = &pb.Key_Address{Address: &pb.AddressKey{Address: b(p.Hash, 20)}}
	case q.Balances:
		k.Value = &pb.Key_Balance{Balance: &pb.BalanceKey{TokenAddress: b(p.Hash, 20), Address: b(p.Subkey, 20)}}
	case q.Holders:
		k.Value = &pb.Key_Holder{Holder: &pb.HolderKey{Balance: p.Amount, Address: b(p.Hash, 20)}}
	case q.Search:
		n, e := strconv.ParseInt(p.Subkey, 10, 32)
		if e != nil {
			return nil, ErrInvalid
		}
		sz := 20
		if n == 1 || n == 2 {
			sz = 32
		}
		k.Value = &pb.Key_Search{Search: &pb.SearchKey{Kind: pb.SearchKind(n), BlockNumber: p.Block, Identity: b(p.Hash, sz)}}
	default:
		return nil, ErrInvalid
	}
	if _, e := keyRead(f, k); e != nil {
		return nil, ErrInvalid
	}
	return k, nil
}
func keyRead(f q.Family, k *pb.Key) (q.Position, error) {
	p := q.Position{}
	if k == nil || !closedMessage(k) {
		return p, ErrUnavailable
	}
	switch v := k.Value.(type) {
	case *pb.Key_Block:
		if f != q.Blocks {
			return p, ErrUnavailable
		}
		p.Block = v.Block.Number
	case *pb.Key_Transaction:
		if f != q.Transactions || !hash(v.Transaction.Hash) {
			return p, ErrUnavailable
		}
		p.Block = v.Transaction.BlockNumber
		p.Index = v.Transaction.TransactionIndex
		p.Hash = hexBytes(v.Transaction.Hash)
	case *pb.Key_Log:
		if f != q.Logs {
			return p, ErrUnavailable
		}
		p.Block = v.Log.BlockNumber
		p.Index = v.Log.LogIndex
	case *pb.Key_Transfer:
		if f != q.Transfers {
			return p, ErrUnavailable
		}
		p.Block = v.Transfer.BlockNumber
		p.Index = v.Transfer.LogIndex
	case *pb.Key_Internal:
		if f != q.Internals || !hash(v.Internal.TransactionHash) || len(v.Internal.TraceAddress) > 256 {
			return p, ErrUnavailable
		}
		p.Block = v.Internal.BlockNumber
		p.Hash = hexBytes(v.Internal.TransactionHash)
		p.Subkey = v.Internal.TraceAddress
	case *pb.Key_Creation:
		if f != q.Contracts && f != q.Tokens || !address(v.Creation.Address) {
			return p, ErrUnavailable
		}
		p.Block = v.Creation.BlockNumber
		p.Hash = hexBytes(v.Creation.Address)
	case *pb.Key_Address:
		if f != q.Addresses || !address(v.Address.Address) {
			return p, ErrUnavailable
		}
		p.Hash = hexBytes(v.Address.Address)
	case *pb.Key_Balance:
		if f != q.Balances || !address(v.Balance.Address) || !address(v.Balance.TokenAddress) {
			return p, ErrUnavailable
		}
		p.Hash = hexBytes(v.Balance.TokenAddress)
		p.Subkey = hexBytes(v.Balance.Address)
	case *pb.Key_Holder:
		if f != q.Holders || !address(v.Holder.Address) || !quantity(v.Holder.Balance) {
			return p, ErrUnavailable
		}
		p.Hash = hexBytes(v.Holder.Address)
		p.Amount = v.Holder.Balance
	case *pb.Key_Search:
		if f != q.Search || v.Search.Kind < 1 || v.Search.Kind > 5 || len(v.Search.Identity) != 20 && len(v.Search.Identity) != 32 {
			return p, ErrUnavailable
		}
		p.Block = v.Search.BlockNumber
		p.Subkey = strconv.Itoa(int(v.Search.Kind))
		p.Hash = hexBytes(v.Search.Identity)
	default:
		return p, ErrUnavailable
	}
	if p.Block > 1<<63-1 {
		return p, ErrUnavailable
	}
	return p, nil
}
func record(f q.Family, k *pb.Key, m map[string]any) (q.Record, error) {
	p, e := keyRead(f, k)
	if e != nil {
		return q.Record{}, e
	}
	raw, e := json.Marshal(m)
	if e != nil || len(raw) > 2<<20 {
		return q.Record{}, ErrTooBroad
	}
	return q.Record{Source: "INDEXER", Family: f, Key: fmt.Sprintf("%s:%d:%d:%s:%s:%s", f, p.Block, p.Index, p.Hash, p.Subkey, p.Amount), Position: p, JSON: raw}, nil
}
func blockRecord(v *pb.Block) (q.Record, error) {
	if v == nil || v.Key == nil || !hash(v.Hash) || !hash(v.ParentHash) {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Blocks, &pb.Key{Value: &pb.Key_Block{Block: v.Key}}, map[string]any{"number": decimal(v.Key.Number), "hash": hexBytes(v.Hash), "parent_hash": hexBytes(v.ParentHash), "timestamp": decimal(v.Timestamp), "gas_used": decimal(v.GasUsed), "gas_limit": decimal(v.GasLimit), "created_at": stamp(v.CreatedAt)})
}
func txRecord(v *pb.Transaction) (q.Record, error) {
	if v == nil || v.Key == nil || !hash(v.Key.Hash) || !address(v.From) || v.To != nil && !address(v.To) || v.ContractAddress != nil && !address(v.ContractAddress) || !quantity(v.Value) || !quantity(v.GasPrice) || v.Status > 1 {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Transactions, &pb.Key{Value: &pb.Key_Transaction{Transaction: v.Key}}, map[string]any{"hash": hexBytes(v.Key.Hash), "block_number": decimal(v.Key.BlockNumber), "tx_index": v.Key.TransactionIndex, "timestamp": decimal(v.BlockTimestamp), "from_address": hexBytes(v.From), "to_address": nullableHex(v.To), "contract_address": nullableHex(v.ContractAddress), "value": v.Value, "gas_used": decimal(v.GasUsed), "gas_price": v.GasPrice, "gas_limit": v.GasLimit, "max_fee_per_gas": v.MaxFeePerGas, "max_priority_fee_per_gas": v.MaxPriorityFeePerGas, "nonce": v.Nonce, "tx_type": v.TransactionType, "input_data": nullableHex(v.InputData), "status": v.Status, "error": v.Error, "revert_reason": v.RevertReason, "created_at": stamp(v.CreatedAt), "categories": v.Categories, "token_transfer_count": v.TokenTransferCount})
}
func logRecord(v *pb.Log) (q.Record, error) {
	if v == nil || v.Key == nil || !hash(v.TransactionHash) || !address(v.Address) {
		return q.Record{}, ErrUnavailable
	}
	for _, t := range [][]byte{v.Topic0, v.Topic1, v.Topic2, v.Topic3} {
		if t != nil && !hash(t) {
			return q.Record{}, ErrUnavailable
		}
	}
	return record(q.Logs, &pb.Key{Value: &pb.Key_Log{Log: v.Key}}, map[string]any{"id": v.Id, "tx_hash": hexBytes(v.TransactionHash), "block_number": decimal(v.Key.BlockNumber), "log_index": v.Key.LogIndex, "address": hexBytes(v.Address), "topic0": nullableHex(v.Topic0), "topic1": nullableHex(v.Topic1), "topic2": nullableHex(v.Topic2), "topic3": nullableHex(v.Topic3), "data": hexBytes(v.Data), "timestamp": v.Timestamp, "removed": v.Removed})
}
func transferRecord(v *pb.TokenTransfer) (q.Record, error) {
	if v == nil || v.Key == nil || !hash(v.TransactionHash) || !address(v.TokenAddress) || !address(v.From) || !address(v.To) || !quantity(v.Value) {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Transfers, &pb.Key{Value: &pb.Key_Transfer{Transfer: v.Key}}, map[string]any{"id": v.Id, "tx_hash": hexBytes(v.TransactionHash), "block_number": decimal(v.Key.BlockNumber), "log_index": v.Key.LogIndex, "token_address": hexBytes(v.TokenAddress), "from_address": hexBytes(v.From), "to_address": hexBytes(v.To), "value": v.Value, "timestamp": v.Timestamp, "transfer_type": v.TransferType, "token_type": v.TokenType, "token_id": v.TokenId, "is_internal": v.IsInternal})
}
func internalRecord(v *pb.InternalTransaction) (q.Record, error) {
	if v == nil || v.Key == nil || !address(v.From) || v.To != nil && !address(v.To) || !quantity(v.Value) {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Internals, &pb.Key{Value: &pb.Key_Internal{Internal: v.Key}}, map[string]any{"id": v.Id, "tx_hash": hexBytes(v.Key.TransactionHash), "block_number": decimal(v.Key.BlockNumber), "trace_address": v.Key.TraceAddress, "from_address": hexBytes(v.From), "to_address": nullableHex(v.To), "value": v.Value, "gas": v.Gas, "gas_used": v.GasUsed, "input": nullableHex(v.Input), "output": nullableHex(v.Output), "call_type": v.CallType, "error": v.Error, "timestamp": v.Timestamp})
}
func contractRecord(v *pb.Contract) (q.Record, error) {
	if v == nil || v.Key == nil || !address(v.Creator) || !hash(v.CreationTransaction) {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Contracts, &pb.Key{Value: &pb.Key_Creation{Creation: v.Key}}, map[string]any{"address": hexBytes(v.Key.Address), "block_number": decimal(v.Key.BlockNumber), "bytecode": hexBytes(v.Bytecode), "bytecode_hash": nullableHex(v.BytecodeHash), "creator": hexBytes(v.Creator), "creation_tx": hexBytes(v.CreationTransaction), "verified": v.Verified, "name": v.Name, "compiler_version": v.CompilerVersion, "created_at": stamp(v.CreatedAt)})
}
func tokenRecord(v *pb.Token) (q.Record, error) {
	if v == nil || v.Key == nil || v.Decimals > 255 {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Tokens, &pb.Key{Value: &pb.Key_Creation{Creation: v.Key}}, map[string]any{"address": hexBytes(v.Key.Address), "block_number": decimal(v.Key.BlockNumber), "symbol": v.Symbol, "name": v.Name, "decimals": v.Decimals, "token_type": v.TokenType, "total_supply": v.TotalSupply, "holder_count": v.HolderCount, "transfer_count": v.TransferCount, "creation_tx": nullableHex(v.CreationTransaction), "l1_address": nullableHex(v.L1Address), "off_chain_updated_at": stamp(v.OffChainUpdatedAt), "created_at": stamp(v.CreatedAt)})
}
func addressRecord(v *pb.Address) (q.Record, error) {
	if v == nil || v.Key == nil || !quantity(v.Balance) {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Addresses, &pb.Key{Value: &pb.Key_Address{Address: v.Key}}, map[string]any{"address": hexBytes(v.Key.Address), "balance": v.Balance, "first_seen": v.FirstSeen, "last_seen": v.LastSeen, "tx_count": v.TransactionCount, "internal_tx_count": v.InternalTransactionCount, "token_transfer_count": v.TokenTransferCount, "sent_count": v.SentCount, "is_contract": v.IsContract, "updated_at": stamp(v.UpdatedAt)})
}
func balanceRecord(v *pb.Balance) (q.Record, error) {
	if v == nil || v.Key == nil || !quantity(v.Balance) {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Balances, &pb.Key{Value: &pb.Key_Balance{Balance: v.Key}}, map[string]any{"address": hexBytes(v.Key.Address), "token_address": hexBytes(v.Key.TokenAddress), "block_number": decimal(v.BlockNumber), "balance": v.Balance, "reorg_epoch": v.ReorgEpoch})
}
func holderRecord(v *pb.Holder) (q.Record, error) {
	if v == nil || v.Key == nil || !address(v.TokenAddress) {
		return q.Record{}, ErrUnavailable
	}
	return record(q.Holders, &pb.Key{Value: &pb.Key_Holder{Holder: v.Key}}, map[string]any{"address": hexBytes(v.Key.Address), "token_address": hexBytes(v.TokenAddress), "balance": v.Key.Balance})
}
func clonedRead(r *pb.ReadContext) *pb.ReadContext {
	if r == nil {
		return nil
	}
	return proto.Clone(r).(*pb.ReadContext)
}
