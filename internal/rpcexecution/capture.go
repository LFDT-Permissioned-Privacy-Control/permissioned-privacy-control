package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/transactioninput"
)

// CaptureEvidence can only be created by a selected acquisition client. It
// supplies bounded local observations under an operational caught-up-node
// assumption, not cryptographic proof that no unseen block exists.
type CaptureEvidence struct {
	origin            *Client
	execution         *CallExecution
	hash              common.Hash
	source            creationfacts.Source
	checkpoint        creationfacts.Checkpoint
	latest            creationfacts.Header
	started, finished time.Time
	mined             bool
}

func (e *CaptureEvidence) Source() creationfacts.Source {
	if e == nil {
		return creationfacts.Source{}
	}
	return e.source
}
func (e *CaptureEvidence) Checkpoint() creationfacts.Checkpoint {
	if e == nil {
		return creationfacts.Checkpoint{}
	}
	return e.checkpoint
}
func (e *CaptureEvidence) Latest() creationfacts.Header {
	if e == nil {
		return creationfacts.Header{}
	}
	return e.latest
}
func (e *CaptureEvidence) Times() (time.Time, time.Time) {
	if e == nil {
		return time.Time{}, time.Time{}
	}
	return e.started, e.finished
}
func (e *CaptureEvidence) KnownMined() bool { return e != nil && e.mined }
func (e *CaptureEvidence) RequireMatches(tx transactioninput.VerifiedTransaction, execution *CallExecution) error {
	if e == nil || e.origin == nil || execution == nil || execution.origin != e.origin || e.execution != execution || !tx.Valid() || !execution.signed || e.hash != tx.Hash() || execution.txHash != tx.Hash() || execution.signer != tx.Signer() || e.source.Network.ChainID != tx.ChainID() || execution.anchor.Profile != e.source.Profile || !e.checkpoint.Valid() || !e.source.Valid() {
		return failure(InvalidEvidence)
	}
	return nil
}

func (c *Client) CaptureSource(network creationfacts.Network) (creationfacts.Source, error) {
	if c == nil || !c.selected || !network.Valid() || network.ChainID != c.binding.ChainID {
		return creationfacts.Source{}, failure(InvalidBinding)
	}
	s := creationfacts.Source{Network: network, Organization: c.binding.OrganizationID, URL: c.binding.URL, CredentialRef: c.credentialRef, CredentialHeader: c.credential.Header, Profile: c.binding.Profile, PragueStart: c.binding.PragueStartInclusive, PragueEnd: c.binding.PragueEndExclusive}
	if !s.Valid() {
		return creationfacts.Source{}, failure(InvalidBinding)
	}
	return s, nil
}

func captureHeader(raw []byte) (creationfacts.Header, error) {
	// The new capture profile requires the same bounded complete header/hash
	// qualification as its owned reference client. Legacy decodeHeader stays
	// unchanged for the earlier acquisition profiles.
	return decodeQualifiedHeader(raw)
}

// ProbeCreationCapture performs at most8 bounded POSTs with no retries. The
// existing rpcBounded transport disables Go's automatic request-body replay.
// Sum of the per-method envelope ceilings is below the3MiB aggregate ceiling.
func (c *Client) ProbeCreationCapture(ctx context.Context, tx transactioninput.VerifiedTransaction, execution *CallExecution, checkpoint creationfacts.Checkpoint, network creationfacts.Network) (*CaptureEvidence, error) {
	if c == nil || execution == nil || execution.origin != c || !execution.signed || !tx.Valid() || execution.txHash != tx.Hash() || execution.signer != tx.Signer() || !checkpoint.Valid() || checkpoint.Network != network.Key || execution.anchor.Number > math.MaxInt64 {
		return nil, failure(InvalidBinding)
	}
	source, err := c.CaptureSource(network)
	if err != nil {
		return nil, err
	}
	if execution.anchor.Profile != source.Profile || execution.anchor.OrganizationID != source.Organization {
		return nil, failure(InvalidBinding)
	}
	ctx, cancel := context.WithTimeout(ctx, creationfacts.CaptureTimeout)
	defer cancel()
	start := time.Now()
	out := &CaptureEvidence{origin: c, execution: execution, hash: tx.Hash(), source: source, checkpoint: checkpoint, started: start.UTC()}
	raw, err := c.rpcBounded(ctx, "eth_chainId", []any{}, 4<<10)
	if err != nil {
		return nil, err
	}
	var chain string
	if json.Unmarshal(raw, &chain) != nil {
		return nil, failure(InvalidEvidence)
	}
	n, valid := quantity(chain, 64)
	if !valid || n.String() != network.ChainID {
		return nil, failure(InvalidEvidence)
	}
	header := func(selector string) (creationfacts.Header, error) {
		b, er := c.rpcBounded(ctx, "eth_getHeaderByNumber", []any{selector}, 16<<10)
		if er != nil {
			return creationfacts.Header{}, er
		}
		return captureHeader(b)
	}
	genesis, err := header("0x0")
	if err != nil || genesis.Number != 0 || genesis.Hash != network.Genesis {
		return nil, failure(InvalidEvidence)
	}
	raw, err = c.rpcBounded(ctx, "eth_syncing", []any{}, 4<<10)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return nil, failure(NodeFailure)
	}
	latest, err := header("latest")
	if err != nil {
		return nil, err
	}
	a := execution.anchor
	if latest.Number < a.Number || a.Number < checkpoint.HighWater.Number || latest.Timestamp < source.PragueStart || latest.Timestamp >= source.PragueEnd {
		return nil, failure(InvalidEvidence)
	}
	wanted := creationfacts.Header{Number: a.Number, Hash: a.Hash, Timestamp: a.Timestamp}
	checkAnchor := func() error {
		h, er := header("0x" + strconv.FormatUint(a.Number, 16))
		if er != nil {
			return er
		}
		if h.Number != wanted.Number || h.Hash != wanted.Hash || h.Timestamp != wanted.Timestamp {
			return failure(InvalidEvidence)
		}
		return nil
	}
	if err = checkAnchor(); err != nil {
		return nil, err
	}
	if checkpoint.HighWater.Number == a.Number {
		if checkpoint.HighWater.Hash != a.Hash {
			return nil, failure(InvalidEvidence)
		}
	} else {
		h, er := header("0x" + strconv.FormatUint(checkpoint.HighWater.Number, 16))
		if er != nil || h.Number != checkpoint.HighWater.Number || h.Hash != checkpoint.HighWater.Hash {
			return nil, failure(InvalidEvidence)
		}
	}
	raw, err = c.rpcResultBounded(ctx, "eth_getTransactionReceipt", []any{tx.Hash().Hex()}, 2<<20, true)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if err = validateCaptureReceipt(raw, tx.Hash()); err != nil {
			return nil, err
		}
		out.mined = true
	}
	if err = checkAnchor(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil || time.Since(start) > creationfacts.CaptureTimeout {
		return nil, failure(NodeFailure)
	}
	out.latest = latest
	out.finished = time.Now().UTC()
	return out, nil
}

func validateCaptureReceipt(raw []byte, hash common.Hash) error {
	fields, err := nullableRawObject(raw, 64, map[string]bool{"to": true, "contractAddress": true})
	if err != nil {
		return err
	}
	for _, name := range []string{"transactionHash", "blockHash"} {
		s, ok := captureStringField(fields, name)
		if !ok {
			return failure(InvalidEvidence)
		}
		b, valid := data(s)
		if !valid || len(b) != 32 || common.BytesToHash(b) == (common.Hash{}) || (name == "transactionHash" && common.BytesToHash(b) != hash) {
			return failure(InvalidEvidence)
		}
	}
	for _, name := range []string{"blockNumber", "transactionIndex", "status"} {
		s, ok := captureStringField(fields, name)
		if !ok {
			return failure(InvalidEvidence)
		}
		n, valid := quantity(s, 64)
		if !valid || !n.IsInt64() || (name == "status" && n.Uint64() > 1) {
			return failure(InvalidEvidence)
		}
	}
	return nil
}

func captureStringField(fields map[string]json.RawMessage, name string) (string, bool) {
	var s string
	raw, ok := fields[name]
	if !ok || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}
