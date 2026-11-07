package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/transactioninput"
)

const GuardRetainedProfileID = "geth-prague-guard-retained/v1"
const MaxGuardSlotsPerAccount = 4096
const MaxGuardSlots = 65536

// TrustedGuardEvidence is an audited orchestration input, like Transport.
// Its Go fields do NOT prove service provenance. guardbridge.Pair checks the
// private originating-service seal before crossing this boundary. Never fill
// this DTO from an HTTP body, arbitrary prepared trace or untrusted provider.
type TrustedGuardEvidence struct {
	Profile                       string
	Calls, Prestate               []byte
	ChainID                       uint64
	TransactionHash, Fingerprint  common.Hash
	HashMode                      uint8
	HeaderHash                    common.Hash
	HeaderNumber, HeaderTimestamp uint64
	HeaderPresent                 bool
}

func (c *Client) QualifyTrustedGuardEvidence(ctx context.Context, tx transactioninput.VerifiedTransaction, e TrustedGuardEvidence) (*CallExecution, error) {
	if c == nil || !c.selected || c.binding.Profile != GuardRetainedProfileID || e.Profile != GuardRetainedProfileID || !tx.Valid() {
		return nil, failure(InvalidBinding)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.AcquisitionTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	to, hasTo := tx.Destination()
	if tx.Creation() || !hasTo || (tx.Type() != 0 && tx.Type() != 2) {
		return nil, failure(UnsupportedEvidence)
	}
	if tx.ChainID() != c.binding.ChainID || strconv.FormatUint(e.ChainID, 10) != tx.ChainID() || e.TransactionHash != tx.Hash() || e.Fingerprint == (common.Hash{}) || (e.HashMode != 0 && e.HashMode != 3) || !e.HeaderPresent || e.HeaderHash == (common.Hash{}) {
		return nil, failure(InvalidEvidence)
	}
	if e.HeaderTimestamp < c.binding.PragueStartInclusive || e.HeaderTimestamp >= c.binding.PragueEndExclusive {
		return nil, failure(UnsupportedEvidence)
	}
	if len(e.Calls) == 0 || len(e.Prestate) == 0 || len(e.Calls) > 16<<20 || len(e.Prestate) > 16<<20 || int64(len(e.Calls)) > c.limits.MaxMuxBytes || int64(len(e.Prestate)) > c.limits.MaxMuxBytes {
		return nil, failure(EvidenceLimit)
	}
	// Own bytes before parsing. The DTO remains caller-owned trusted input;
	// callers must not mutate it concurrently during this invocation.
	calls, pre := bytes.Clone(e.Calls), bytes.Clone(e.Prestate)
	call := signedCall(tx)
	expected := executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: call.from, To: executionfacts.Address{Value: to, Known: true}, Input: call.input, Value: call.value}
	tree, err := executionfacts.Parse(calls, expected, executionfacts.GethCallTracerWithLogsProfile(), c.limits.Trace)
	if err != nil {
		return nil, failure(InvalidEvidence)
	}
	codes, total, err := decodePrestateProfile(pre, c.limits, true)
	if err != nil {
		return nil, err
	}
	anchor := Anchor{ChainID: tx.ChainID(), Hash: e.HeaderHash, Number: e.HeaderNumber, Timestamp: e.HeaderTimestamp, Profile: GuardRetainedProfileID, OrganizationID: c.binding.OrganizationID}
	raw := append([]byte(`{"callTracer":`), calls...)
	raw = append(raw, []byte(`,"prestateTracer":`)...)
	raw = append(raw, pre...)
	raw = append(raw, '}')
	execution, err := c.finishEvidence(ctx, call, anchor, tree, codes, total, raw)
	if err != nil {
		return nil, err
	}
	execution.signed, execution.signer, execution.txHash, execution.hashMode = true, tx.Signer(), tx.Hash(), e.HashMode
	return execution, nil
}

func checkGuardStorage(raw []byte, total *int) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return failure(InvalidEvidence)
	}
	seen := map[common.Hash]bool{}
	for d.More() {
		if len(seen) >= MaxGuardSlotsPerAccount || *total >= MaxGuardSlots {
			return failure(EvidenceLimit)
		}
		key, err := d.Token()
		if err != nil {
			return failure(InvalidEvidence)
		}
		s, ok := key.(string)
		if !ok || len(s) != 66 {
			return failure(InvalidEvidence)
		}
		b, ok := data(s)
		if !ok || len(b) != 32 {
			return failure(InvalidEvidence)
		}
		slot := common.BytesToHash(b)
		if seen[slot] {
			return failure(InvalidEvidence)
		}
		seen[slot] = true
		var value string
		if d.Decode(&value) != nil || len(value) != 66 {
			return failure(InvalidEvidence)
		}
		b, ok = data(value)
		if !ok || len(b) != 32 {
			return failure(InvalidEvidence)
		}
		*total++
	}
	if _, err = d.Token(); err != nil {
		return failure(InvalidEvidence)
	}
	if _, err = d.Token(); err != io.EOF {
		return failure(InvalidEvidence)
	}
	return nil
}
