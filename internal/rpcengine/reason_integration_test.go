package rpcengine_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/rpcengine"
)

func TestObservedReasonsCaptureActualBranchesWithoutChangingCallerResponse(t *testing.T) {
	for _, name := range []string{"method", "sender", "policy", "wallet source", "auth", "shape", "expired view", "cancel", "deadline"} {
		t.Run(name, func(t *testing.T) {
			f, n := newFixture(), &node{}
			var clock atomic.Int64
			wallets := linkedWallets()
			call := map[string]any{"to": addressA}
			want := activityreasondata.NotRecorded
			class := rpcengine.DeniedCompletion
			switch name {
			case "method":
				f.groups[0].AllowedMethods = []string{"eth_getCode"}
				want = activityreasondata.MethodNotAllowed
			case "sender":
				call["from"] = addressB
				want = activityreasondata.SenderNotLinked
			case "policy":
				f.bindings[0].Allow[0].StorageAddress = addressC
				call["data"] = "0x01020304"
				want = activityreasondata.PolicyNoMatchingRule
			case "wallet source":
				call["from"] = walletAddress
				wallets = walletResolver(func(context.Context, string) (nativeadmission.WalletSnapshot, error) {
					return nativeadmission.WalletSnapshot{}, errors.New("private source failure: do not record")
				})
				class = rpcengine.UnavailableCompletion
			case "auth":
				want, class = activityreasondata.AuthRequired, rpcengine.UnauthenticatedCompletion
			case "shape":
				want, class = activityreasondata.InvalidRequestShape, rpcengine.InvalidCompletion
			case "expired view":
				call["from"] = walletAddress
				wallets = walletResolver(func(ctx context.Context, actor string) (nativeadmission.WalletSnapshot, error) {
					value, err := linkedWallets().Load(ctx, actor)
					clock.Store(now + 300)
					return value, err
				})
				want, class = activityreasondata.CredentialsExpired, rpcengine.UnauthenticatedCompletion
			case "cancel":
				want, class = activityreasondata.RequestCancelled, rpcengine.UnavailableCompletion
			case "deadline":
				want, class = activityreasondata.ExecutionUnavailable, rpcengine.UnavailableCompletion
			}
			e, tok, _ := engine(t, f, n, wallets, &clock)
			if name == "auth" {
				tok = "not-a-token"
			}
			raw := encoded(t, map[string]any{"jsonrpc": "2.0", "id": 9, "method": "eth_call", "params": []any{call}})
			if name == "shape" {
				raw = []byte(`{"jsonrpc":"2.0","id":9,"method":"eth_call","params":[null]}`)
			}
			ctx := t.Context()
			if name == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if name == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			result := e.CallObserved(ctx, tok, orgA, raw)
			m, err := result.MetadataFor(e)
			if err != nil || m.Class != class || m.Reason != want && !(want == activityreasondata.NotRecorded && m.Reason == "") {
				t.Fatalf("selected diagnostic: %+v, want %s/%v: %v", m, want, class, err)
			}
			body, err := result.MarshalResponseFor(e)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{string(want), "private source failure", "PolicyNoMatchingRule"} {
				if private != "" && bytes.Contains(body, []byte(private)) {
					t.Fatal("admin-only diagnostic leaked to ordinary caller", private)
				}
			}
			if name == "method" || name == "sender" {
				if m.ActorID == "" || m.OrganizationID != orgA {
					t.Fatal("verified own-org diagnostic lost attribution", m)
				}
				methods, _ := n.counts()
				if len(methods) != 0 {
					t.Fatal("early denial reached node", methods)
				}
				_, legacy := request(t, e, tok, orgA, call, nil)
				// IDs differ in the legacy helper; the actual closed error must not.
				if !bytes.Contains(body, []byte(`"code":-32001`)) || !bytes.Contains(legacy, []byte(`"code":-32001`)) {
					t.Fatal("ordinary denial response changed", string(body), string(legacy))
				}
			}
		})
	}
}
