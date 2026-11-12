package rpcengine

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/admissionsharedata"
	"privacy-proxy/internal/explorerquery"
	wire "privacy-proxy/internal/explorerv2data"
)

// Delegates are concrete owned operations. They verify once, retain that View,
// and run under the outer REST recorder rather than making an HTTP/RPC roundtrip.
func (e *ExplorerEngine) delegateExplorer(ctx context.Context, assertion MetadataAssertion, org string, r *ExplorerOperationResult) *ExplorerOperationResult {
	label := r.request.operation.Label
	method := r.request.operation.Gate
	params := []any{}
	if strings.HasPrefix(label, "explorer.address_") {
		params = []any{r.request.query.Address, "latest"}
	}
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	fence, err := admissionsharedata.NewFence(ctx, 20*time.Second)
	if err != nil {
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	var result json.RawMessage
	if strings.HasPrefix(label, "explorer.address_") {
		r.state = e.config.State.QueryObserved(ctx, assertion, org, raw)
		m, err := r.state.MetadataFor(e.config.State)
		if err != nil || m.Class != SuccessfulCompletion {
			return r.fail(403, "denied", DeniedCompletion)
		}
		r.captured.ActorID, r.captured.OrganizationID = m.ActorID, m.OrganizationID
		result = r.state.observation.ResultJSON()
	} else {
		r.metadata = e.config.Metadata.QueryObserved(ctx, assertion, org, raw)
		m, err := r.metadata.MetadataFor(e.config.Metadata)
		if err != nil || m.Class != SuccessfulCompletion {
			return r.fail(403, "denied", DeniedCompletion)
		}
		r.captured.ActorID, r.captured.OrganizationID = m.ActorID, m.OrganizationID
		result = r.metadata.observation.ResultJSON()
	}
	var value any
	switch label {
	case "explorer.chain_id", "explorer.head", "explorer.address_balance":
		var encoded string
		if json.Unmarshal(result, &encoded) != nil {
			return r.fail(503, "unavailable", UnavailableCompletion)
		}
		n, ok := new(big.Int).SetString(strings.TrimPrefix(encoded, "0x"), 16)
		if !ok || n.Sign() < 0 || n.BitLen() > 256 {
			return r.fail(503, "unavailable", UnavailableCompletion)
		}
		q := qbig(n)
		if label == "explorer.chain_id" {
			value = wire.ChainID{ChainID: q}
		} else if label == "explorer.head" {
			value = wire.LatestBlock{Number: q}
		} else {
			value = wire.NativeBalance{Address: r.request.query.Address, Balance: q}
		}
	case "explorer.address_code", "explorer.address_is_contract", "explorer.address_contract":
		var code string
		if json.Unmarshal(result, &code) != nil || !strings.HasPrefix(code, "0x") {
			return r.fail(503, "unavailable", UnavailableCompletion)
		}
		if label == "explorer.address_code" {
			value = wire.Code{Address: r.request.query.Address, Code: wire.Hex(code)}
		} else if label == "explorer.address_is_contract" {
			value = wire.IsContract{Address: r.request.query.Address, IsContract: code != "0x"}
		} else {
			out := wire.Contract{Address: r.request.query.Address}
			v := wire.Hex(code)
			out.Bytecode = &v
			if contract, ok := r.state.view.Contract(common.HexToAddress(r.request.query.Address)); ok && contract.Associated() {
				registry := contract.RegistryMetadata()
				var entries []json.RawMessage
				if json.Unmarshal(registry.ABI, &entries) == nil {
					out.ABI = &entries
				}
			}
			value = out
		}
	case "explorer.sync_status", "explorer.indexer_progress", "explorer.catchup":
		ov, ok := r.metadata.view.Org(r.captured.OrganizationID)
		if !ok || !ov.IsOrgAdmin() && !ov.IsOrgReadonlyAdmin() {
			return r.fail(403, "denied", DeniedCompletion)
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
		if len(data.Rows) != 1 {
			return r.fail(503, "unavailable", UnavailableCompletion)
		}
		var sync wire.SyncStatus
		var progress wire.IndexerProgress
		for _, row := range append(append([]explorerquery.Record{}, data.Rows...), data.Context...) {
			f, err := fieldsOf(row)
			if err != nil {
				return r.fail(503, "unavailable", UnavailableCompletion)
			}
			if row.Family == explorerquery.Sync {
				q, err := f.quantity("last_indexed_block")
				if err != nil || q == nil {
					return r.fail(503, "unavailable", UnavailableCompletion)
				}
				sync = wire.SyncStatus{LastIndexedBlock: *q, IsSyncing: f.boolean("is_syncing"), UpdatedAt: f.text("updated_at")}
			}
			if row.Family == explorerquery.Progress {
				lo, err := f.quantity("min_fetched_block")
				if err != nil || lo == nil {
					return r.fail(503, "unavailable", UnavailableCompletion)
				}
				hi, err := f.quantity("max_fetched_block")
				if err != nil || hi == nil {
					return r.fail(503, "unavailable", UnavailableCompletion)
				}
				progress = wire.IndexerProgress{MinFetchedBlock: *lo, MaxFetchedBlock: *hi, BackfillComplete: f.boolean("backfill_complete"), UpdatedAt: f.text("updated_at")}
			}
		}
		if label == "explorer.sync_status" {
			value = sync
		} else if label == "explorer.indexer_progress" {
			value = progress
		} else {
			if progress.MinFetchedBlock == "" {
				return r.fail(503, "unavailable", UnavailableCompletion)
			}
			value = wire.Catchup{Indexer: progress, Sync: sync}
		}
	default:
		return r.fail(503, "unavailable", UnavailableCompletion)
	}
	r.body, err = json.Marshal(value)
	if err != nil || len(r.body) > MaxExplorerResponseBytes {
		return r.fail(422, "too_broad", UnavailableCompletion)
	}
	r.captured.HTTPStatus = 200
	r.captured.Class = SuccessfulCompletion
	return r
}
