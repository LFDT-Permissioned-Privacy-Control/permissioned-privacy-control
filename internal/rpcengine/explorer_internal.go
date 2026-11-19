package rpcengine

import (
	"context"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/rpcexecution"
	"strings"
)

func qualifyExplorerInternalFrames(ctx context.Context, b *rpcexecution.IncludedHistoryBatch, rows []explorerquery.Record) error {
	wanted := []rpcexecution.IndexedInternalFrame{}
	for _, r := range rows {
		if r.Family != explorerquery.Internals {
			continue
		}
		f, e := fieldsOf(r)
		if e != nil {
			return e
		}
		bn, e := f.integer("block_number")
		if e != nil {
			return e
		}
		value, e := f.quantity("value")
		if e != nil || value == nil {
			return errExplorer
		}
		gas, e := f.quantity("gas")
		if e != nil {
			return e
		}
		used, e := f.quantity("gas_used")
		if e != nil {
			return e
		}
		frame := rpcexecution.IndexedInternalFrame{TransactionHash: common.HexToHash(f.text("tx_hash")), BlockNumber: bn, Path: f.text("trace_address"), From: common.HexToAddress(f.text("from_address")), Value: string(*value), Type: f.text("call_type"), Error: f.text("error")}
		if to := f.nullable("to_address"); to != nil {
			a := common.HexToAddress(*to)
			frame.To = &a
		}
		if gas != nil {
			n, e := f.integer("gas")
			if e != nil {
				return e
			}
			frame.Gas = &n
		}
		if used != nil {
			n, e := f.integer("gas_used")
			if e != nil {
				return e
			}
			frame.GasUsed = &n
		}
		decode := func(s string) ([]byte, error) {
			if s == "" {
				return nil, nil
			}
			return hex.DecodeString(strings.TrimPrefix(s, "0x"))
		}
		frame.Input, e = decode(f.text("input"))
		if e != nil {
			return e
		}
		frame.Output, e = decode(f.text("output"))
		if e != nil {
			return e
		}
		wanted = append(wanted, frame)
	}
	if len(wanted) == 0 {
		return nil
	}
	return b.VerifyIndexedFrames(ctx, wanted)
}
