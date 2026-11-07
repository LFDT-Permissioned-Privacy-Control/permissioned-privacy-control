package rpcexecution

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/transactioninput"
)

const SignedCallProfileID = "geth-prague-signed-call/v1"
const MaxBroadcastResponseBytes = 1 << 20

func signedChain(tx transactioninput.VerifiedTransaction, chain string) bool {
	if !tx.Valid() || tx.ChainID() != chain {
		return false
	}
	n, err := strconv.ParseUint(chain, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == chain
}

// signedCall is used only after opaque transaction validation. Unlike a
// simulation, every gas, fee and nonce field comes from the signed envelope.
func signedCall(tx transactioninput.VerifiedTransaction) Call {
	to, _ := tx.Destination()
	chain, _ := new(big.Int).SetString(tx.ChainID(), 10)
	call := Call{from: tx.Signer(), to: to, fromSupplied: true, input: tx.Input(), value: tx.Value(), chainID: chain, creation: tx.Creation(), signedInput: true, signedNonce: tx.Nonce()}
	call.wire = map[string]any{"from": call.from.Hex(), "to": to.Hex(), "input": "0x" + common.Bytes2Hex(call.input), "value": "0x" + call.value.Text(16), "gas": "0x" + strconv.FormatUint(tx.Gas(), 16), "nonce": "0x" + strconv.FormatUint(tx.Nonce(), 16), "chainId": "0x" + chain.Text(16), "type": "0x" + strconv.FormatUint(uint64(tx.Type()), 16)}
	if call.creation {
		delete(call.wire, "to")
	}
	if tx.Type() == 0 || tx.Type() == 1 {
		call.wire["gasPrice"] = "0x" + tx.GasPrice().Text(16)
	} else {
		call.wire["maxFeePerGas"] = "0x" + tx.FeeCap().Text(16)
		call.wire["maxPriorityFeePerGas"] = "0x" + tx.TipCap().Text(16)
	}
	if tx.Type() != 0 {
		entries := []any{}
		for _, entry := range tx.AccessList() {
			keys := []any{}
			for _, key := range entry.StorageKeys {
				keys = append(keys, key.Hex())
			}
			entries = append(entries, map[string]any{"address": entry.Address.Hex(), "storageKeys": keys})
		}
		call.wire["accessList"] = entries
	}
	return call
}

// AcquireSigned owns this fixed tracing profile. It cannot relabel simulation
// or retained Guard evidence into signed evidence.
func (c *Client) AcquireSigned(ctx context.Context, tx transactioninput.VerifiedTransaction) (*CallExecution, error) {
	if c == nil || !c.selected || c.binding.Profile != SignedCallProfileID || !signedChain(tx, c.binding.ChainID) {
		return nil, failure(InvalidBinding)
	}
	if tx.Creation() {
		return nil, failure(UnsupportedEvidence)
	}
	block, _ := ParseBlockSelector(nil)
	call := signedCall(tx)
	overrides := map[string]any{call.from.Hex(): map[string]any{"nonce": "0x" + strconv.FormatUint(tx.Nonce(), 16)}}
	execution, err := c.acquire(ctx, call, block, overrides)
	if err != nil {
		return nil, err
	}
	execution.signed, execution.signer, execution.txHash = true, tx.Signer(), tx.Hash()
	return execution, nil
}

// BroadcastRaw invokes the selected node exactly once. Any error can be an
// ambiguous submission and must never cause automatic resubmission.
func (c *Client) BroadcastRaw(ctx context.Context, tx transactioninput.VerifiedTransaction) (common.Hash, error) {
	if c == nil || !c.selected || (c.binding.Profile != SignedCallProfileID && c.binding.Profile != GuardRetainedProfileID && c.binding.Profile != LifecycleSignedProfileID && c.binding.Profile != LifecycleGuardProfileID) || !signedChain(tx, c.binding.ChainID) {
		return common.Hash{}, failure(InvalidBinding)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := c.rpcBounded(ctx, "eth_sendRawTransaction", []any{tx.RawHex()}, MaxBroadcastResponseBytes)
	if err != nil {
		return common.Hash{}, err
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || len(value) != 66 {
		return common.Hash{}, failure(InvalidEvidence)
	}
	b, ok := data(value)
	if !ok || len(b) != common.HashLength || common.BytesToHash(b) != tx.Hash() {
		return common.Hash{}, failure(InvalidEvidence)
	}
	return tx.Hash(), nil
}
