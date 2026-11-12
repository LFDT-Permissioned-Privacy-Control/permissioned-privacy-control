package rpcengine

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
)

const MaxExplorerResponseBytes = 8 << 20

var errExplorer = errors.New("invalid Explorer operation")

type ExplorerConfig struct {
	Snapshot                *policybundle.CatalogSnapshot
	History                 *HistoryEngine
	State                   *StateEngine
	Metadata                *MetadataEngine
	Index                   explorerquery.Source
	IndexExpected           explorerquery.Binding
	CursorKey, PseudonymKey []byte
}
type ExplorerEngine struct {
	config   ExplorerConfig
	metadata explorerquery.Metadata
	cursor   cipher.AEAD
	policy   policybundle.Digest
}

func NewExplorer(c ExplorerConfig) (*ExplorerEngine, error) {
	if c.Snapshot == nil || !c.Snapshot.HistoryConsumerEnabled() || c.History == nil || c.State == nil || c.Metadata == nil || c.Index == nil || !c.IndexExpected.Valid() || len(c.CursorKey) != 32 || len(c.PseudonymKey) < 32 || len(c.PseudonymKey) > 64 || bytes.Equal(c.CursorKey, c.PseudonymKey) {
		return nil, errExplorer
	}
	if c.History.snapshot != c.Snapshot || !c.History.SharesStateSnapshot(c.State) || !c.History.SharesMetadataSnapshot(c.Metadata) || c.IndexExpected.Network != c.History.network {
		return nil, errExplorer
	}
	for _, client := range c.History.clients {
		if explorerCapacity(client.Bounds()) < 1 {
			return nil, errExplorer
		}
	}
	metadata := c.Index.Metadata()
	if metadata.Binding != c.IndexExpected || !metadata.Identity.Valid() || metadata.Mode != "existing-indexer-fixed-reads/v1" {
		return nil, errExplorer
	}
	for _, method := range c.Snapshot.Methods() {
		if activitymethoddata.Reserved(method.Name) || activitymethoddata.Reserved(method.Canonical) {
			return nil, errExplorer
		}
	}
	block, err := aes.NewCipher(c.CursorKey)
	if err != nil {
		return nil, errExplorer
	}
	sealed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errExplorer
	}
	c.CursorKey = nil
	c.PseudonymKey = append([]byte{}, c.PseudonymKey...)
	raw, _ := json.Marshal(struct {
		Version    string
		Manifest   policybundle.Digest
		Operations []activitymethoddata.Operation
	}{"ops-explorer-current-read/v2", c.Snapshot.Metadata().ManifestDigest, activitymethoddata.Operations()})
	d := sha256.Sum256(raw)
	return &ExplorerEngine{config: c, metadata: metadata, cursor: sealed, policy: policybundle.Digest("sha256:" + hex.EncodeToString(d[:]))}, nil
}
func (e *ExplorerEngine) OperationBinding() MetadataOperationBinding {
	if e == nil {
		return MetadataOperationBinding{}
	}
	b := e.config.History.OperationBinding()
	b.Methods = activitymethoddata.ExplorerLabels()
	b.PolicyDigest = e.policy
	return b
}
func (e *ExplorerEngine) SharesHistory(history *HistoryEngine) bool {
	return e != nil && e.config.History == history
}
func (e *ExplorerEngine) SharesState(state *StateEngine) bool {
	return e != nil && e.config.State == state
}
func (e *ExplorerEngine) SharesMetadata(metadata *MetadataEngine) bool {
	return e != nil && e.config.Metadata == metadata
}

type ExplorerOperationMetadata struct {
	Method, ActorID, OrganizationID string
	PolicyDigest                    policybundle.Digest
	HTTPStatus                      int
	Class                           CompletionClass
}
type ExplorerOperationResult struct {
	owner    *ExplorerEngine
	request  explorerRequest
	current  *historyfacts.Current
	pass     *explorerquery.ReadPass
	batch    *rpcexecution.IncludedHistoryBatch
	state    *StateOperationResult
	metadata *MetadataOperationResult
	captured ExplorerOperationMetadata
	body     []byte
}

func (r *ExplorerOperationResult) fail(status int, code string, class CompletionClass) *ExplorerOperationResult {
	r.captured.HTTPStatus = status
	r.captured.Class = class
	r.body, _ = json.Marshal(struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}{Error: struct {
		Code string `json:"code"`
	}{code}})
	return r
}
func (e *ExplorerEngine) QueryHTTPObserved(ctx context.Context, assertion MetadataAssertion, org, path, rawQuery string) *ExplorerOperationResult {
	r := &ExplorerOperationResult{owner: e, captured: ExplorerOperationMetadata{Method: "explorer.invalid_request", HTTPStatus: 503, Class: UnavailableCompletion}}
	if e == nil || ctx == nil || ctx.Err() != nil {
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	r.captured.PolicyDigest = e.policy
	request, err := parseExplorerRequest(path, rawQuery)
	if err != nil {
		return r.fail(400, "invalid_request", InvalidCompletion)
	}
	r.request = request
	r.captured.Method = request.operation.Label
	if assertion.kind != 2 {
		return r.fail(401, "unauthenticated", UnauthenticatedCompletion)
	}
	if explorerScalar(request.operation.Label) {
		return e.delegateExplorer(ctx, assertion, org, r)
	}
	current, err := e.config.History.facts.Begin(ctx, assertion.token, org, request.operation.Gate)
	if err != nil {
		return r.fail(403, "denied", DeniedCompletion)
	}
	r.current = current
	r.captured.ActorID = current.OriginalView().ActorID()
	r.captured.OrganizationID = current.Organization()
	if err = e.openExplorerCursor(r); err != nil {
		return r.fail(409, "cursor_stale", InvalidCompletion)
	}
	fence, err := newExplorerQueryFence(ctx, current)
	if err != nil {
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	r.request.query.Fence = fence
	pass, err := e.config.Index.ReadCohort(ctx, r.request.query)
	if err != nil {
		return explorerSourceFailure(r, err)
	}
	if pass.ValidateFor(e.metadata) != nil {
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	r.pass = pass
	data := pass.Data()
	client := e.config.History.clients[HistoryBindingKey{current.Organization(), current.CredentialRef()}]
	if client == nil {
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	// One bounded, fully processed prefix. Never advance across an unqualified
	// candidate. A short/empty page can carry an authenticated continuation.
	count, hashes, err := explorerPrefix(data, client.Bounds())
	if err != nil {
		return r.fail(422, "too_broad", UnavailableCompletion)
	}
	var anchor *rpcexecution.HistoryHeader
	if data.Upper != nil {
		anchor = &rpcexecution.HistoryHeader{Number: data.Upper.Number, Hash: common.HexToHash(data.Upper.Hash)}
	}
	d, done := current.OriginalFence()
	anchors := []rpcexecution.HistoryHeader{}
	if r.request.query.Family == explorerquery.Blocks {
		count = min(count, explorerCapacity(client.Bounds()))
		for _, row := range data.Rows[:count] {
			f, e := fieldsOf(row)
			if e != nil {
				return r.fail(503, "unavailable", UnavailableCompletion)
			}
			n, e := f.integer("number")
			if e != nil || !explorerquery.ValidHash(f.text("hash")) {
				return r.fail(503, "unavailable", UnavailableCompletion)
			}
			anchors = append(anchors, rpcexecution.HistoryHeader{Number: n, Hash: common.HexToHash(f.text("hash"))})
		}
	}
	batch, err := client.AcquireExplorerBatch(ctx, hashes, anchor, anchors, rpcexecution.HistoryOperationFence{Deadline: d, Done: done}, current.ChargedBytes()+2*pass.ChargedBytes())
	if err != nil {
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	r.batch = batch
	renderer, err := newExplorerRender(r, data)
	if err != nil {
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	if !current.Profile().Strict() && len(hashes) > 0 {
		allowance := batch.RemainingWorkingBytes() / 2
		if allowance < 256 || batch.ReserveWorkingBytes(2*allowance) != nil {
			return r.fail(422, "too_broad", UnavailableCompletion)
		}
		r.current, err = current.WithSharesWithin(ctx, hashes, allowance)
		if err != nil {
			return r.fail(503, "unavailable", UnavailableCompletion)
		}
	}
	body, err := renderer.render(data, count)
	if err != nil {
		return explorerSourceFailure(r, err)
	}
	if len(body) > MaxExplorerResponseBytes {
		return r.fail(422, "too_broad", UnavailableCompletion)
	}
	r.body = body
	r.captured.HTTPStatus = 200
	r.captured.Class = SuccessfulCompletion
	return r
}
func explorerSourceFailure(r *ExplorerOperationResult, err error) *ExplorerOperationResult {
	switch {
	case errors.Is(err, explorerquery.ErrTooBroad):
		return r.fail(422, "too_broad", UnavailableCompletion)
	case errors.Is(err, explorerquery.ErrConflict):
		return r.fail(409, "cursor_stale", InvalidCompletion)
	default:
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
}
func explorerPrefix(data explorerquery.Data, l rpcexecution.HistoryReadLimits) (int, []common.Hash, error) {
	seen := map[common.Hash]bool{}
	hashes := []common.Hash{}
	n := 0
	ceiling := explorerCapacity(l)
	for _, row := range data.Rows {
		var fields map[string]json.RawMessage
		if json.Unmarshal(row.JSON, &fields) != nil {
			return 0, nil, errExplorer
		}
		var hash string
		if row.Family == explorerquery.Transactions {
			_ = json.Unmarshal(fields["hash"], &hash)
		} else {
			_ = json.Unmarshal(fields["tx_hash"], &hash)
		}
		if hash != "" {
			if !explorerquery.ValidHash(hash) {
				return 0, nil, errExplorer
			}
			h := common.HexToHash(hash)
			if !seen[h] {
				if len(hashes) >= ceiling {
					break
				}
				seen[h] = true
				hashes = append(hashes, h)
			}
		}
		n++
	}
	if n == 0 && len(data.Rows) > 0 {
		return 0, nil, explorerquery.ErrTooBroad
	}
	return n, hashes, nil
}
func (r *ExplorerOperationResult) MetadataFor(e *ExplorerEngine) (ExplorerOperationMetadata, error) {
	if r == nil || r.owner != e || e == nil {
		return ExplorerOperationMetadata{}, errExplorer
	}
	return r.captured, nil
}
func (r *ExplorerOperationResult) MarshalResponseFor(e *ExplorerEngine) ([]byte, error) {
	if r == nil || r.owner != e || e == nil || len(r.body) == 0 || len(r.body) > MaxExplorerResponseBytes {
		return nil, errExplorer
	}
	return append([]byte{}, r.body...), nil
}
func (r *ExplorerOperationResult) RequireDeliverable(ctx context.Context, e *ExplorerEngine) error {
	if r == nil || e == nil || r.owner != e || ctx == nil || ctx.Err() != nil {
		return errExplorer
	}
	if r.pass != nil && e.config.Index.Recheck(ctx, r.pass) != nil {
		return errExplorer
	}
	if r.state != nil {
		return r.state.RequireDeliverable(ctx, e.config.State)
	}
	if r.metadata != nil {
		return r.metadata.RequireDeliverable(ctx, e.config.Metadata)
	}
	if r.current != nil {
		if r.current.Recheck(ctx) != nil {
			return errExplorer
		}
		if r.batch != nil && r.batch.Recheck(ctx) != nil {
			return errExplorer
		}
		return r.current.RequireLive(ctx)
	}
	if r.captured.HTTPStatus == 200 {
		return errExplorer
	}
	return nil
}
func explorerScalar(label string) bool {
	switch label {
	case "explorer.chain_id", "explorer.head", "explorer.address_balance", "explorer.address_code", "explorer.address_contract", "explorer.address_is_contract", "explorer.sync_status", "explorer.indexer_progress", "explorer.catchup":
		return true
	}
	return false
}

// Keep future cursors bounded by the exact original JWT, independent sources,
// current wallet set and selected upper anchor, never a refreshed principal.
type explorerCursor struct {
	Version                     int
	Actor, Organization, Wallet string
	Auth                        [32]byte
	Policy                      policybundle.Digest
	Query                       [32]byte
	Source                      explorerquery.Binding
	Upper                       *explorerquery.Anchor
	After                       explorerquery.Position
	Expires                     int64
}

func cursorExpiry(current *historyfacts.Current) int64 {
	return current.OriginalView().ExpiresAt().Unix()
}
func sortedHashes(hashes []common.Hash) []common.Hash {
	out := append([]common.Hash{}, hashes...)
	sort.Slice(out, func(i, j int) bool { return out[i].Hex() < out[j].Hex() })
	return out
}

func explorerCapacity(l rpcexecution.HistoryReadLimits) int {
	ceiling := min(64, l.MaxParents, l.MaxHeaders-1, (l.MaxRPCItems-16)/6)
	ceil := func(n int) int { return (n + l.MaxBatchItems - 1) / l.MaxBatchItems }
	for ceiling > 0 && 4*ceil(3)+2*ceil(ceiling)+4*ceil(ceiling+1) > l.MaxHTTPAttempts {
		ceiling--
	}
	return ceiling
}
func newExplorerQueryFence(ctx context.Context, current *historyfacts.Current) (historyfacts.Fence, error) {
	if ctx == nil || ctx.Err() != nil || current == nil {
		return historyfacts.Fence{}, errExplorer
	}
	fence := current.OperationFence()
	if fence.Check() != nil {
		return historyfacts.Fence{}, errExplorer
	}
	return fence, nil
}
