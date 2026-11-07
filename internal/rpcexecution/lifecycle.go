package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/transactioninput"
)

const (
	LifecycleCallProfileID   = policybundle.RuntimeLifecycleNodeEvidenceProfileID
	LifecycleSignedProfileID = "geth-prague-lifecycle-signed/v1"
	LifecycleGuardProfileID  = "geth-prague-lifecycle-guard/v1"
)

func lifecycleProfile(profile string) bool {
	return profile == LifecycleCallProfileID || profile == LifecycleSignedProfileID || profile == LifecycleGuardProfileID || profile == SimulationCallProfileID
}

func lifecycleLimits(l Limits) bool {
	d := DefaultLimits()
	return l.valid() && l.MaxMuxBytes <= d.MaxMuxBytes && l.MaxPrestateAccounts <= d.MaxPrestateAccounts &&
		l.MaxCodeBytesPerAccount <= d.MaxCodeBytesPerAccount && l.MaxTotalCodeBytes <= d.MaxTotalCodeBytes &&
		l.MaxAnchoredCodeLookups <= d.MaxAnchoredCodeLookups && l.AcquisitionTimeout <= d.AcquisitionTimeout &&
		l.Trace.MaxRawBytes <= d.Trace.MaxRawBytes && l.Trace.MaxRecords <= d.Trace.MaxRecords &&
		l.Trace.MaxInputBytes <= d.Trace.MaxInputBytes && l.Trace.MaxAggregateInputBytes <= d.Trace.MaxAggregateInputBytes &&
		l.Trace.MaxTextBytes <= d.Trace.MaxTextBytes && l.Trace.MaxLogs <= d.Trace.MaxLogs && l.Trace.MaxAggregateLogBytes <= d.Trace.MaxAggregateLogBytes
}

func (c *Client) AcquireLifecycleCall(ctx context.Context, call Call, block BlockSelector) (*CallExecution, error) {
	if c == nil || !c.selected || c.binding.Profile != LifecycleCallProfileID || call.creation || call.signedInput || call.wire == nil || call.value == nil || block.selector == "" {
		return nil, failure(InvalidBinding)
	}
	return c.acquireProfile(ctx, call, block, nil, true)
}

func (c *Client) AcquireLifecycleSigned(ctx context.Context, tx transactioninput.VerifiedTransaction) (*CallExecution, error) {
	if c == nil || !c.selected || c.binding.Profile != LifecycleSignedProfileID || !signedChain(tx, c.binding.ChainID) {
		return nil, failure(InvalidBinding)
	}
	block, _ := ParseBlockSelector(nil)
	call := signedCall(tx)
	overrides := map[string]any{call.from.Hex(): map[string]any{"nonce": "0x" + strconv.FormatUint(tx.Nonce(), 16)}}
	e, err := c.acquireProfile(ctx, call, block, overrides, true)
	if err != nil {
		return nil, err
	}
	e.signed, e.signer, e.txHash = true, tx.Signer(), tx.Hash()
	return e, nil
}

func (c *Client) finishLifecycle(ctx context.Context, call Call, anchor Anchor, tree *executionfacts.Tree, codes map[common.Address]CodeInfo, total int, raw []byte, lookups int) (*CallExecution, error) {
	if lookups < 0 || lookups > c.limits.MaxAnchoredCodeLookups {
		return nil, failure(EvidenceLimit)
	}
	query := func(method string, a common.Address) (json.RawMessage, error) {
		if lookups >= c.limits.MaxAnchoredCodeLookups {
			return nil, failure(EvidenceLimit)
		}
		lookups++
		responseLimit := int64(1024)
		if method == "eth_getCode" {
			responseLimit += int64(2 * min(c.limits.MaxCodeBytesPerAccount, c.limits.MaxTotalCodeBytes-total))
		}
		return c.rpcBounded(ctx, method, []any{a.Hex(), map[string]any{"blockHash": anchor.Hash.Hex(), "requireCanonical": false}}, min(c.limits.MaxMuxBytes, responseLimit))
	}
	ensure := func(a common.Address, needNonce bool) (CodeInfo, error) {
		if ctx.Err() != nil {
			return CodeInfo{}, failure(NodeFailure)
		}
		code, present := codes[a]
		if !present {
			rawCode, err := query("eth_getCode", a)
			if err != nil {
				return CodeInfo{}, err
			}
			b, err := decodeCode(rawCode, min(c.limits.MaxCodeBytesPerAccount, c.limits.MaxTotalCodeBytes-total))
			if err != nil {
				return CodeInfo{}, err
			}
			total += len(b)
			code = CodeInfo{code: b, hash: crypto.Keccak256Hash(b), precompile: precompile(a)}
		}
		if delegation(code.code) {
			return CodeInfo{}, failure(UnsupportedEvidence)
		}
		if call.creationNonceKnown && a == call.from && !present {
			code.nonce, code.nonceKnown = call.creationNonce, true
		}
		if needNonce && !code.nonceKnown {
			if call.signedInput && a == call.from {
				code.nonce = call.signedNonce // Selected override, never anchor substitution.
			} else {
				rawNonce, err := query("eth_getTransactionCount", a)
				if err != nil {
					return CodeInfo{}, err
				}
				var text string
				if json.Unmarshal(rawNonce, &text) != nil {
					return CodeInfo{}, failure(InvalidEvidence)
				}
				value, ok := quantity(text, 64)
				if !ok {
					return CodeInfo{}, failure(InvalidEvidence)
				}
				code.nonce = value.Uint64()
			}
			code.nonceKnown = true
		}
		codes[a] = code
		return code, nil
	}
	// Own one records copy; timeline code references this private input. Public
	// Tree.Records and CodeInfo.Bytes always return detached bytes.
	records := tree.Records()
	timeline, err := buildTimeline(ctx, records, &total, c.limits, ensure)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return &CallExecution{call: call, anchor: anchor, tree: tree, codes: codes, raw: bytes.Clone(raw), recordCount: len(records), timeline: timeline}, nil
}
