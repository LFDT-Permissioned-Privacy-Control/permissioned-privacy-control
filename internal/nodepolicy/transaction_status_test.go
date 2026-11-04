package nodepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestTransactionStatusRequiresExactBindingAndCanonicalOutcome(t *testing.T) {
	hash := "0x" + strings.Repeat("11", 32)
	for _, test := range []string{"pending", "included", "wrong_hash", "invalid_created", "pending_created", "produced", "resync"} {
		t.Run(test, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     string   `json:"id"`
					Method string   `json:"method"`
					Params []string `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				if req.Method != "ops_transactionStatus" || len(req.Params) != 1 || req.Params[0] != hash {
					t.Errorf("wrong request %+v", req)
				}
				result := map[string]any{"transaction_hash": hash, "principal_id": "user-a", "org_id": "org-a", "context_id": "context-a", "boot_id": testBootID, "execution": map[string]any{"status": "pending", "facts_version": uint64(7), "block_hash": nil, "block_number": nil, "reason_code": "", "created": []any{}}}
				outcome := result["execution"].(map[string]any)
				outcome["finalized"], outcome["finalized_block_hash"], outcome["finalized_block_number"] = false, nil, nil
				if test == "included" || test == "invalid_created" {
					outcome["status"] = "included"
					outcome["block_hash"] = hash
					outcome["block_number"] = 1
				}
				if test == "invalid_created" || test == "pending_created" {
					outcome["created"] = []any{map[string]any{"address": "0x" + strings.Repeat("22", 20), "org_id": "foreign", "principal_id": "user-a"}}
				}
				if test == "produced" {
					outcome["status"] = "produced"
				}
				if test == "wrong_hash" {
					result["transaction_hash"] = "0x" + strings.Repeat("00", 32)
				}
				response := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}
				if test == "resync" {
					delete(response, "result")
					response["error"] = map[string]any{"code": -32011, "message": "private details"}
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer s.Close()
			client, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			status, err := client.TransactionStatus(context.Background(), hash)
			if test == "pending" || test == "included" {
				if err != nil || status.Execution.Status != test {
					t.Fatalf("status=%+v err=%v", status, err)
				}
			} else if err == nil {
				t.Fatal("invalid status accepted")
			}
			if test == "resync" && err != ErrNodeResync {
				t.Fatalf("resync error not classified: %v", err)
			}
		})
	}
}

// One entry the node answered invalidly is an error for that hash only: the
// other entries of the batch are decoded and returned (independent review,
// finding 1). Call-level faults (boot id, head, entry count) still fail the
// call; they are not caused by one transaction.
func TestBatchedStatusIsolatesAnInvalidEntry(t *testing.T) {
	hashes := []string{"0x" + strings.Repeat("11", 32), "0x" + strings.Repeat("22", 32), "0x" + strings.Repeat("33", 32), "0x" + strings.Repeat("44", 32)}
	created := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"address": fmt.Sprintf("0x%040x", i+1), "org_id": "org-a", "principal_id": "user-a"}
		}
		return out
	}
	entry := func(hash string, contracts int) map[string]any {
		blockHash := "0x" + strings.Repeat("bb", 32)
		return map[string]any{"transaction_hash": hash, "principal_id": "user-a", "org_id": "org-a", "context_id": "context-a", "pooled": false,
			"execution": map[string]any{"status": "included", "facts_version": 7, "block_hash": blockHash, "block_number": 5, "finalized": false, "finalized_block_hash": nil, "finalized_block_number": nil, "reason_code": "", "created": created(contracts)}}
	}
	unknownField := entry(hashes[2], 1)
	unknownField["surprise"] = true
	hugeBlock := entry(hashes[3], 1)
	hugeBlock["execution"].(map[string]any)["block_number"] = uint64(1) << 63 // above BIGINT: would fail the whole write
	s := rpcServer(t, func(string, []json.RawMessage) (any, string) {
		return map[string]any{"boot_id": testBootID, "finalized": nil, "canonical_epoch": 0, "statuses": []any{
			entry(hashes[0], MaxCreatedContracts+1), // more contracts than a transaction can create
			entry(hashes[1], MaxCreatedContracts),   // the node's maximum
			unknownField,
			hugeBlock,
		}}, ""
	})
	defer s.Close()
	c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	batch, err := c.TransactionStatuses(context.Background(), hashes)
	if err != nil || len(batch.Statuses) != 4 {
		t.Fatalf("one invalid entry failed the batch: %+v %v", batch, err)
	}
	for _, i := range []int{0, 2, 3} {
		if e := batch.Statuses[i]; e == nil || !errors.Is(e.Err, ErrInvalidStatus) || !errors.Is(e.Err, ErrNodeResponse) {
			t.Fatalf("entry %d: %+v, want an invalid-status error for that hash only", i, e)
		}
	}
	if e := batch.Statuses[1]; e == nil || e.Err != nil || len(e.Status.Execution.Created) != MaxCreatedContracts {
		t.Fatalf("valid entry with the maximum created contracts: %+v", e)
	}
}

// The created-contracts bound is the node's: it refuses a transaction at its
// MAX_CHECKS+1-th policy-checked frame (calls and creates together), so an
// included transaction never created more. A node change that allows more
// must raise OPS's bound with it, never silently truncate (finding 1).
func TestCreatedContractsBoundIsTheNodesFrameLimit(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "node", "reth", "src", "policy.rs"))
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^const MAX_CHECKS: usize = (\d+);`).FindSubmatch(source)
	if match == nil {
		t.Fatal("node/reth/src/policy.rs no longer declares MAX_CHECKS: re-derive the created-contracts bound")
	}
	if limit, _ := strconv.Atoi(string(match[1])); limit != MaxCreatedContracts {
		t.Fatalf("node MAX_CHECKS = %d, OPS MaxCreatedContracts = %d", limit, MaxCreatedContracts)
	}
	for _, check := range []string{
		`if self.calls.len() >= MAX_CHECKS {`,                               // the frame cap in call and create
		`self.calls.clear();`,                                               // per transaction
		`return Err(EVMError::Transaction(PolicyTxError::Denied(reason)));`, // a denied transaction is never included
	} {
		if !strings.Contains(string(source), check) {
			t.Fatalf("node policy no longer contains %q: re-derive the created-contracts bound", check)
		}
	}
}

// N7 (final wire): a batched entry may be the string "not_found", the node's
// definitive canonical miss; any other string is that entry's invalid answer.
// With senders a miss must come with receipts[i] == false. The single call's
// miss is -32014 (P7 §4.1, finding F7).
func TestBatchedStatusDecodesTheDefinitiveMiss(t *testing.T) {
	hashes := []string{"0x" + strings.Repeat("11", 32), "0x" + strings.Repeat("22", 32), "0x" + strings.Repeat("33", 32)}
	s := rpcServer(t, func(method string, params []json.RawMessage) (any, string) {
		if method == "ops_transactionStatus" {
			return nil, `{"code":-32014,"message":"transaction not found"}`
		}
		result := map[string]any{"boot_id": testBootID, "finalized": nil, "canonical_epoch": 0, "statuses": []any{"not_found", "missing", nil}}
		if len(params) == 2 {
			result["receipts"], result["sender_nonces"] = []any{false, false, true}, nil
			result["statuses"] = []any{"not_found", nil, "not_found"} // the last has a receipt: invalid
		}
		return result, ""
	})
	defer s.Close()
	c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	batch, err := c.TransactionStatuses(context.Background(), hashes)
	if err != nil || batch.Statuses[0] == nil || !batch.Statuses[0].NotFound || batch.Statuses[1] == nil || !errors.Is(batch.Statuses[1].Err, ErrInvalidStatus) || batch.Statuses[2] != nil {
		t.Fatalf("batch %+v %v", batch, err)
	}
	evidence, err := c.TransactionEvidence(context.Background(), hashes, []string{"0x" + strings.Repeat("aa", 20)})
	if err != nil || !evidence.Statuses[0].NotFound || evidence.Statuses[1] != nil || evidence.Statuses[2] == nil || !errors.Is(evidence.Statuses[2].Err, ErrInvalidStatus) {
		t.Fatalf("evidence %+v %v", evidence, err)
	}
	if _, err := c.TransactionStatus(context.Background(), hashes[0]); !NodeNotFound(err) || NodeRefused(err) {
		t.Fatalf("single-call miss: %v", err)
	}
}
