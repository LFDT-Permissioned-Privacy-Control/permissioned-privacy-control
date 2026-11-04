package nodepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

const testBootID = "0123456789abcdef0123456789abcdef"

// rpcServer answers every call with the result (or error) respond returns.
func rpcServer(t *testing.T, respond func(method string, params []json.RawMessage) (result any, rpcErr string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     string            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Error(err)
			return
		}
		result, rpcErr := respond(req.Method, req.Params)
		id, _ := json.Marshal(req.ID)
		if rpcErr != "" {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(id)+`,"error":`+rpcErr+`}`)
			return
		}
		raw, _ := json.Marshal(result)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(id)+`,"result":`+string(raw)+`}`)
	}))
}

func readyStatus(boot string) map[string]any {
	return map[string]any{"protocol_version": 1, "network": identityFixture().Network, "capabilities": RequiredCapabilities(), "version": 7, "digest": strings.Repeat("a", 64), "expires_at": 1100, "ready": true, "reason": "", "boot_id": boot}
}

// T16 wire (final): every successful result carries the node's boot id; an
// acknowledgement is recorded against the boot id of the response that
// carried it, so a missing or malformed one is a protocol violation.
func TestNodeResultsCarryValidatedBootID(t *testing.T) {
	expected, identity, rawTx := signedSubmissionFixture(t, false)
	hash := expected.BindingHash
	for _, boot := range []string{testBootID, "", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef", "absent"} {
		t.Run(boot, func(t *testing.T) {
			withBoot := func(result map[string]any) map[string]any {
				if boot == "absent" {
					delete(result, "boot_id")
				} else {
					result["boot_id"] = boot
				}
				return result
			}
			s := rpcServer(t, func(method string, _ []json.RawMessage) (any, string) {
				switch method {
				case "ops_policyStatus":
					return withBoot(readyStatus(boot)), ""
				case "ops_policyApply":
					return withBoot(map[string]any{"version": 7, "digest": strings.Repeat("a", 64), "expires_at": 1100}), ""
				case "ops_submitTransaction":
					return withBoot(map[string]any{"transaction_hash": hash, "context_id": expected.ContextID, "status": "accepted"}), ""
				default:
					return withBoot(map[string]any{"transaction_hash": hash, "principal_id": "user-a", "org_id": "org-a", "context_id": "context-a",
						"execution": map[string]any{"status": "pending", "facts_version": 7, "block_hash": nil, "block_number": nil, "finalized": false, "finalized_block_hash": nil, "finalized_block_number": nil, "reason_code": "", "created": []any{}}}), ""
				}
			})
			defer s.Close()
			c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			status, statusErr := c.PolicyStatus(ctx)
			applied, applyErr := c.ApplyPolicy(ctx, []byte(`{"kind":"heartbeat"}`))
			submitted, submitErr := c.SubmitTransaction(ctx, identity, rawTx)
			outcome, outcomeErr := c.TransactionStatus(ctx, hash)
			if boot != testBootID {
				for name, err := range map[string]error{"status": statusErr, "apply": applyErr, "submit": submitErr, "transaction status": outcomeErr} {
					if !errors.Is(err, ErrNodeResponse) {
						t.Fatalf("%s accepted boot id %q: %v", name, boot, err)
					}
				}
				return
			}
			if statusErr != nil || applyErr != nil || submitErr != nil || outcomeErr != nil {
				t.Fatalf("valid responses refused: %v %v %v %v", statusErr, applyErr, submitErr, outcomeErr)
			}
			if status.BootID != testBootID || applied.BootID != testBootID || submitted.BootID != testBootID || outcome.BootID != testBootID {
				t.Fatalf("boot ids not decoded: %q %q %q %q", status.BootID, applied.BootID, submitted.BootID, outcome.BootID)
			}
		})
	}
}

// A node that does not report boot ids cannot be recovered after a restart
// (OPS could not tell which deliveries it lost), so it is not ready.
func TestBootIDCapabilityIsRequired(t *testing.T) {
	if !slices.Contains(RequiredCapabilities(), CapabilityBootID) {
		t.Fatalf("required capabilities %v lack %s", RequiredCapabilities(), CapabilityBootID)
	}
}

// T18 wire (final): -32013 with data.reason nonce_used or replaced is a
// definitive pool answer for these bytes now; any other reason is a protocol
// violation; other codes stay opaque rejections.
func TestPoolRejectionReasonIsClassified(t *testing.T) {
	_, identity, rawTx := signedSubmissionFixture(t, false)
	for _, test := range []struct {
		name, rpcErr string
		reason       string
		want         error
	}{
		{"nonce_used", `{"code":-32013,"message":"transaction pool rejected","data":{"reason":"nonce_used"}}`, PoolNonceUsed, ErrNodeRejected},
		{"replaced", `{"code":-32013,"message":"transaction pool rejected","data":{"reason":"replaced"}}`, PoolReplaced, ErrNodeRejected},
		{"unknown_reason", `{"code":-32013,"message":"transaction pool rejected","data":{"reason":"private detail"}}`, "", ErrNodeResponse},
		{"missing_data", `{"code":-32013,"message":"transaction pool rejected"}`, "", ErrNodeResponse},
		{"generic", `{"code":-32000,"message":"private execution request rejected"}`, "", ErrNodeRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := rpcServer(t, func(string, []json.RawMessage) (any, string) { return nil, test.rpcErr })
			defer s.Close()
			c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.SubmitTransaction(context.Background(), identity, rawTx)
			if !errors.Is(err, test.want) {
				t.Fatalf("error %v, want %v", err, test.want)
			}
			var rejection *PoolRejection
			if got := errors.As(err, &rejection); got != (test.reason != "") || (got && rejection.Reason != test.reason) {
				t.Fatalf("pool rejection %+v (%v), want reason %q", rejection, got, test.reason)
			}
			if strings.Contains(err.Error(), "private detail") {
				t.Fatal("node detail leaked into the error")
			}
		})
	}
}

// Keeper deliveries travel on the recovery lane, never competing with client
// submissions for transaction connections.
func TestRecoverySubmissionUsesTheRecoveryLane(t *testing.T) {
	expected, identity, rawTx := signedSubmissionFixture(t, false)
	s := rpcServer(t, func(string, []json.RawMessage) (any, string) {
		return map[string]any{"transaction_hash": expected.BindingHash, "context_id": expected.ContextID, "status": "accepted", "boot_id": testBootID}, ""
	})
	defer s.Close()
	c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	var transactionLane, recoveryLane atomic.Int64
	c.transaction = &http.Client{Transport: countingTransport{&transactionLane, s.Client().Transport}}
	c.recovery = &http.Client{Transport: countingTransport{&recoveryLane, s.Client().Transport}}
	submitted, err := c.SubmitRecovery(context.Background(), identity, rawTx)
	if err != nil || submitted.BootID != testBootID {
		t.Fatalf("recovery submission %+v %v", submitted, err)
	}
	if recoveryLane.Load() != 1 || transactionLane.Load() != 0 {
		t.Fatalf("recovery submission lanes: recovery=%d transaction=%d", recoveryLane.Load(), transactionLane.Load())
	}
}

type countingTransport struct {
	n    *atomic.Int64
	next http.RoundTripper
}

func (c countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return c.next.RoundTrip(req)
}

// Option A (G9): the batched status call, used only when the node advertises
// it, is decoded as strictly as the single call, null for an unknown hash.
func TestBatchedTransactionStatusesAreStrict(t *testing.T) {
	hashes := []string{"0x" + strings.Repeat("11", 32), "0x" + strings.Repeat("22", 32)}
	entry := func(hash string) map[string]any {
		return map[string]any{"transaction_hash": hash, "principal_id": "user-a", "org_id": "org-a", "context_id": "context-a", "pooled": true,
			"execution": map[string]any{"status": "pending", "facts_version": 7, "block_hash": nil, "block_number": nil, "finalized": false, "finalized_block_hash": nil, "finalized_block_number": nil, "reason_code": "", "created": []any{}}}
	}
	for _, test := range []string{"ok", "reordered", "short", "no_boot", "bad_head"} {
		t.Run(test, func(t *testing.T) {
			s := rpcServer(t, func(method string, params []json.RawMessage) (any, string) {
				if method != "ops_transactionStatuses" || len(params) != 1 {
					t.Errorf("wrong call %s %d", method, len(params))
				}
				statuses := []any{entry(hashes[0]), nil}
				head := map[string]any{"number": 9, "hash": "0x" + strings.Repeat("33", 32), "timestamp": 1000}
				switch test {
				case "reordered":
					statuses = []any{entry(hashes[1]), nil}
				case "short":
					statuses = statuses[:1]
				case "bad_head":
					head["hash"] = "0x12"
				}
				result := map[string]any{"boot_id": testBootID, "finalized": head, "canonical_epoch": 3, "statuses": statuses}
				if test == "no_boot" {
					delete(result, "boot_id")
				}
				return result, ""
			})
			defer s.Close()
			c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			batch, err := c.TransactionStatuses(context.Background(), hashes)
			if test == "reordered" {
				// An entry for another hash is that position's invalid answer,
				// never another transaction's outcome; the call stands.
				if err != nil || batch.Statuses[0] == nil || !errors.Is(batch.Statuses[0].Err, ErrInvalidStatus) {
					t.Fatalf("misplaced entry: %+v %v", batch, err)
				}
				return
			}
			if test != "ok" {
				if !errors.Is(err, ErrNodeResponse) {
					t.Fatalf("invalid batch accepted: %+v %v", batch, err)
				}
				return
			}
			if err != nil || batch.BootID != testBootID || batch.CanonicalEpoch != 3 || batch.Finalized == nil || batch.Finalized.Number != 9 || len(batch.Statuses) != 2 || batch.Statuses[0] == nil || !batch.Statuses[0].Pooled || batch.Statuses[1] != nil {
				t.Fatalf("batch %+v %v", batch, err)
			}
			if batch.Statuses[0].Status.BootID != testBootID {
				t.Fatal("entries carry the batch's boot id")
			}
		})
	}
	if _, err := (&Client{}).TransactionStatuses(context.Background(), make([]string, MaxStatusBatch+1)); !errors.Is(err, ErrIdentity) {
		t.Fatalf("oversized batch sent: %v", err)
	}
}

// A2 P5: with a control URL, fact publication and node status go to the
// node's control listener; everything else stays on the main listener.
func TestControlLaneUsesTheControlListener(t *testing.T) {
	expected, identity, rawTx := signedSubmissionFixture(t, false)
	var main, control atomic.Int64
	serve := func(counter *atomic.Int64) *httptest.Server {
		return rpcServer(t, func(method string, _ []json.RawMessage) (any, string) {
			counter.Add(1)
			if method == "ops_policyStatus" {
				return readyStatus(testBootID), ""
			}
			return map[string]any{"transaction_hash": expected.BindingHash, "context_id": expected.ContextID, "status": "accepted", "boot_id": testBootID}, ""
		})
	}
	mainServer, controlServer := serve(&main), serve(&control)
	defer mainServer.Close()
	defer controlServer.Close()
	c, err := NewPooledClient(mainServer.URL, "private-test-token", identityFixture().Network, DefaultLanes())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WithControlEndpoint("http://user:secret@example.invalid"); err == nil {
		t.Fatal("a control URL with credentials accepted")
	}
	if err := c.WithControlEndpoint(controlServer.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PolicyStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubmitTransaction(context.Background(), identity, rawTx); err != nil {
		t.Fatal(err)
	}
	if control.Load() != 1 || main.Load() != 1 {
		t.Fatalf("control=%d main=%d, want 1/1", control.Load(), main.Load())
	}
}

// Only the node's own opaque refusal (-32000) counts as a definitive answer
// about a transaction; internal errors and limits do not.
func TestNodeRefusedIsTheOpaqueRefusalOnly(t *testing.T) {
	if !NodeRefused(&RejectedError{Code: -32000}) || NodeRefused(&RejectedError{Code: -32603}) || NodeRefused(ErrNodeUnavailable) || NodeRefused(ErrNodeRejected) {
		t.Fatal("NodeRefused misclassifies")
	}
	if !errors.Is(&RejectedError{Code: -32603}, ErrNodeRejected) {
		t.Fatal("a rejection is a node rejection")
	}
}

// ops_transactionStatuses (final, A3): with the optional second parameter
// (senders) the answer also carries receipts (true/false/null per hash) and
// the senders' nonces at the finalized block (null when finality is unknown);
// without it neither field may appear. finalized is null while only genesis is
// final. Malformed evidence is a protocol error; an unrequested field too.
func TestTransactionEvidenceIsStrict(t *testing.T) {
	hashes := []string{"0x" + strings.Repeat("11", 32), "0x" + strings.Repeat("22", 32)}
	senders := []string{"0x" + strings.Repeat("aa", 20)}
	head := map[string]any{"number": 9, "hash": "0x" + strings.Repeat("33", 32), "timestamp": 1000}
	for _, test := range []string{"ok", "no_finality", "unrequested_receipts", "short_receipts", "nonces_without_head", "short_nonces", "null_nonce", "missing_receipts", "genesis_head"} {
		t.Run(test, func(t *testing.T) {
			s := rpcServer(t, func(method string, params []json.RawMessage) (any, string) {
				result := map[string]any{"boot_id": testBootID, "finalized": head, "canonical_epoch": 0, "statuses": []any{nil, nil}, "receipts": []any{false, nil}, "sender_nonces": []any{5}}
				switch test {
				case "no_finality":
					result["finalized"], result["sender_nonces"] = nil, nil
				case "unrequested_receipts":
				case "short_receipts":
					result["receipts"] = []any{false}
				case "nonces_without_head":
					result["finalized"] = nil
				case "short_nonces":
					result["sender_nonces"] = []any{}
				case "null_nonce":
					result["sender_nonces"] = []any{nil}
				case "missing_receipts":
					delete(result, "receipts")
				case "genesis_head":
					result["finalized"] = map[string]any{"number": 0, "hash": "0x" + strings.Repeat("44", 32), "timestamp": 0}
				}
				if test == "unrequested_receipts" {
					if len(params) != 1 {
						t.Errorf("statuses-only call sent %d params", len(params))
					}
				} else if len(params) != 2 {
					t.Errorf("evidence call sent %d params", len(params))
				}
				return result, ""
			})
			defer s.Close()
			c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
			if err != nil {
				t.Fatal(err)
			}
			if test == "unrequested_receipts" {
				if _, err := c.TransactionStatuses(context.Background(), hashes); !errors.Is(err, ErrNodeResponse) {
					t.Fatalf("evidence fields without a senders parameter accepted: %v", err)
				}
				return
			}
			batch, err := c.TransactionEvidence(context.Background(), hashes, senders)
			switch test {
			case "ok":
				if err != nil || batch.Finalized == nil || len(batch.Receipts) != 2 || batch.Receipts[0] == nil || *batch.Receipts[0] || batch.Receipts[1] != nil || len(batch.SenderNonces) != 1 || batch.SenderNonces[0] != 5 {
					t.Fatalf("evidence %+v %v", batch, err)
				}
			case "no_finality":
				if err != nil || batch.Finalized != nil || batch.SenderNonces != nil {
					t.Fatalf("no finality: %+v %v", batch, err)
				}
			default:
				if !errors.Is(err, ErrNodeResponse) {
					t.Fatalf("invalid evidence accepted: %+v %v", batch, err)
				}
			}
		})
	}
	for _, bad := range [][]string{{}, {"0x" + strings.Repeat("AA", 20)}, {"0xaa"}, make([]string, MaxStatusBatch+1)} {
		if _, err := (&Client{}).TransactionEvidence(context.Background(), hashes, bad); !errors.Is(err, ErrIdentity) {
			t.Fatalf("invalid senders %v sent: %v", bad, err)
		}
	}
}
