package perfgate

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMockNodeStampsArrivalReplyAndReportsStalledSenders(t *testing.T) {
	node, clock, public, _ := testNode(t, time.Second)
	key := mustKey(t)
	tx0, raw0 := signedTransfer(t, key, 0)
	_, raw2 := signedTransfer(t, key, 2) // nonce 1 never arrives
	before := time.Now()
	resultString(t, call(t, public.URL, "", "eth_sendRawTransaction", raw0))
	resultString(t, call(t, public.URL, "", "eth_sendRawTransaction", raw2))
	stamps := node.Stamps()
	s := stamps[strings.ToLower(tx0.Hash().Hex())]
	if s.Arrived < before.UnixNano() || s.Replied < s.Arrived || s.Finalized != 0 {
		t.Fatalf("stamp before inclusion %+v", s)
	}
	clock.Advance(time.Second)
	block := node.ProduceBlock()
	if got := node.Stamps()[strings.ToLower(tx0.Hash().Hex())].Finalized; got != block.Time.Add(time.Second).UnixNano() {
		t.Fatalf("finalized stamp %d", got)
	}
	if senders, txs := node.Stalled(); senders != 1 || txs != 1 {
		t.Fatalf("stalled senders=%d txs=%d, want 1/1", senders, txs)
	}
	if st := node.Stats(); st.Pooled != 1 || st.Included != 1 {
		t.Fatalf("counters %+v", st)
	}
}

func TestMockProcessServesAndReportsOverControlAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}
	proc, err := StartMockProcess(context.Background(), MockNodeConfig{ChainID: 31337, DeploymentID: "perfgate-test", PrivateToken: "private-token-0123456789", BlockTime: 100 * time.Millisecond, FinalityLag: 0}, t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	key := mustKey(t)
	tx, raw := signedTransfer(t, key, 0)
	hash := strings.ToLower(tx.Hash().Hex())
	if err := proc.Index([]Tx{{Hash: hash, Nonce: 0, Sender: 0}}, []string{"0x0000000000000000000000000000000000000abc"}); err != nil {
		t.Fatal(err)
	}
	if got := resultString(t, call(t, proc.PublicURL, "", "eth_sendRawTransaction", raw)); got != hash {
		t.Fatalf("hash %s", got)
	}
	if r := call(t, proc.PrivateURL, "", "ops_policyStatus"); r.status != http.StatusUnauthorized {
		t.Fatalf("private API without token: %d", r.status)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		stats, err := proc.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if stats.FinalizedTxs == 1 {
			break
		}
		if time.Now().After(deadline) {
			b, _ := json.Marshal(stats)
			t.Fatalf("not finalized: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	stamps, err := proc.Stamps()
	if err != nil || stamps[hash].Finalized == 0 || stamps[hash].Arrived == 0 {
		t.Fatalf("stamps %+v %v", stamps[hash], err)
	}
	// The indexed sender, not the recovered one, owns the nonce.
	if got := resultString(t, call(t, proc.PublicURL, "", "eth_getTransactionCount", "0x0000000000000000000000000000000000000abc", "latest")); got != "0x1" {
		t.Fatalf("indexed sender nonce %s", got)
	}
}
