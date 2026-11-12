package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/transactioninput"
)

func (c *Client) nodeSigningBound() bool {
	return c != nil && c.selected && c.networkBound && (c.binding.Profile == LifecycleSignedProfileID || c.binding.Profile == LifecycleGuardProfileID)
}

// PrepareNodeCall only reads defaults. The node signs later; no node-owned
// transaction is broadcast by this adapter, including on an uncertain failure.
func (c *Client) PrepareNodeCall(ctx context.Context, call Call) (Call, error) {
	if !c.nodeSigningBound() || call.wire == nil || !call.fromSupplied || call.signedInput {
		return Call{}, failure(InvalidBinding)
	}
	if call.chainID != nil && call.chainID.String() != c.binding.ChainID {
		return Call{}, failure(InvalidCall)
	}
	if err := c.RequireBoundNetwork(ctx); err != nil {
		return Call{}, err
	}
	wire := call.Object()
	wire["chainId"] = "0x" + mustChain(c.binding.ChainID)
	if wire["nonce"] == nil {
		raw, err := c.rpcBounded(ctx, "eth_getTransactionCount", []any{call.from.Hex(), "pending"}, 1024)
		if err != nil {
			return Call{}, err
		}
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return Call{}, failure(InvalidEvidence)
		}
		if _, ok := quantity(text, 64); !ok {
			return Call{}, failure(InvalidEvidence)
		}
		wire["nonce"] = text
	}
	if wire["gasPrice"] == nil && wire["maxFeePerGas"] == nil {
		raw, err := c.rpcBounded(ctx, "eth_gasPrice", []any{}, 1024)
		if err != nil {
			return Call{}, err
		}
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return Call{}, failure(InvalidEvidence)
		}
		if _, ok := quantity(text, 256); !ok {
			return Call{}, failure(InvalidEvidence)
		}
		if wire["type"] == "0x2" || wire["maxPriorityFeePerGas"] != nil {
			if tip, ok := wire["maxPriorityFeePerGas"].(string); ok {
				a, _ := quantity(text, 256)
				b, _ := quantity(tip, 256)
				if b.Cmp(a) > 0 {
					text = tip
				}
			}
			wire["maxFeePerGas"] = text
		} else {
			wire["gasPrice"] = text
		}
	}
	if wire["type"] == nil {
		typ := "0x0"
		if wire["maxFeePerGas"] != nil || wire["maxPriorityFeePerGas"] != nil {
			typ = "0x2"
		} else if wire["accessList"] != nil {
			typ = "0x1"
		}
		wire["type"] = typ
	}
	if wire["type"] != "0x0" && wire["accessList"] == nil {
		wire["accessList"] = []any{}
	}
	if wire["type"] == "0x2" && wire["maxPriorityFeePerGas"] == nil {
		wire["maxPriorityFeePerGas"] = "0x0"
	}
	b, _ := json.Marshal(wire)
	return NormalizeSimulationCall(b)
}
func mustChain(chain string) string { n, _ := new(big.Int).SetString(chain, 10); return n.Text(16) }

// SignNodeCall uses the existing selected raw lane's exact credential and
// verifies every filled field before returning opaque signed evidence.
func (c *Client) SignNodeCall(ctx context.Context, call Call) (transactioninput.VerifiedTransaction, error) {
	var zero transactioninput.VerifiedTransaction
	if !c.nodeSigningBound() || call.wire == nil || !call.fromSupplied || call.wire["gas"] == nil || call.wire["nonce"] == nil {
		return zero, failure(InvalidBinding)
	}
	if err := c.RequireBoundNetwork(ctx); err != nil {
		return zero, err
	}
	raw, err := c.rpcBounded(ctx, "eth_signTransaction", []any{call.Object()}, 2<<20)
	if err != nil {
		return zero, err
	}
	// Reth returns bytes; geth returns {raw,tx}. The independently decoded raw
	// envelope is the authority, never the accompanying declared tx object.
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		parts, err := closedRawObject(raw, 2)
		if err != nil || len(parts) != 2 || parts["raw"] == nil || parts["tx"] == nil {
			return zero, failure(InvalidEvidence)
		}
		raw = parts["raw"]
	}
	text, err := includedString(raw, 2+2*transactioninput.DefaultLimits().MaxRawBytes)
	if err != nil {
		return zero, err
	}
	tx, err := transactioninput.DecodeRaw(text, c.binding.ChainID, transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		return zero, failure(InvalidEvidence)
	}
	if tx.Signer() != call.from || tx.Creation() != call.creation || tx.Value().Cmp(call.value) != 0 || !bytes.Equal(tx.Input(), call.input) {
		return zero, failure(InvalidEvidence)
	}
	if !call.creation {
		to, ok := tx.Destination()
		if !ok || to != call.to {
			return zero, failure(InvalidEvidence)
		}
	}
	actual := signedCall(tx).Object()
	for _, field := range []string{"gas", "nonce", "chainId", "type", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas"} {
		if value, ok := call.wire[field].(string); ok {
			other, ok := actual[field].(string)
			a, valid := quantity(value, 256)
			b, validB := quantity(other, 256)
			if !ok || !valid || !validB || a.Cmp(b) != 0 {
				return zero, failure(InvalidEvidence)
			}
		}
	}
	if list, ok := call.wire["accessList"]; ok {
		b, _ := json.Marshal(list)
		var wanted types.AccessList
		if json.Unmarshal(b, &wanted) != nil {
			return zero, failure(InvalidEvidence)
		}
		v, _ := json.Marshal(actual["accessList"])
		var got types.AccessList
		if json.Unmarshal(v, &got) != nil || !reflect.DeepEqual(wanted, got) {
			return zero, failure(InvalidEvidence)
		}
	}
	return tx, nil
}
