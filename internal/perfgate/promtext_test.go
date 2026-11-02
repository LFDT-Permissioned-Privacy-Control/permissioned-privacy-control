package perfgate

import (
	"testing"
	"time"
)

func TestHistogramDeltas(t *testing.T) {
	before := `# HELP x
privacyproxy_rpc_request_duration_seconds_bucket{method="eth_sendRawTransaction",le="0.001"} 0
privacyproxy_rpc_request_duration_seconds_bucket{method="eth_sendRawTransaction",le="0.005"} 10
privacyproxy_rpc_request_duration_seconds_bucket{method="eth_sendRawTransaction",le="+Inf"} 10
privacyproxy_rpc_request_duration_seconds_sum{method="eth_sendRawTransaction"} 0.03
privacyproxy_rpc_request_duration_seconds_count{method="eth_sendRawTransaction"} 10
`
	after := `privacyproxy_rpc_request_duration_seconds_bucket{method="eth_sendRawTransaction",le="0.001"} 50
privacyproxy_rpc_request_duration_seconds_bucket{method="eth_sendRawTransaction",le="0.005"} 108
privacyproxy_rpc_request_duration_seconds_bucket{method="eth_sendRawTransaction",le="+Inf"} 110
privacyproxy_rpc_request_duration_seconds_sum{method="eth_sendRawTransaction"} 0.23
privacyproxy_rpc_request_duration_seconds_count{method="eth_sendRawTransaction"} 110
`
	got := histogramDeltas(before, after)
	s, ok := got[`privacyproxy_rpc_request_duration_seconds{method="eth_sendRawTransaction"}`]
	if !ok || s.Count != 100 || s.P50LeMS != 1 || s.P99LeMS != -1 || s.MeanMS < 1.99 || s.MeanMS > 2.01 {
		t.Fatalf("summary %+v (keys %v)", s, got)
	}
}

func TestMockNodeFinalityCounts(t *testing.T) {
	node, clock, _, _ := testNode(t, 2_000_000_000) // 2 s
	key := mustKey(t)
	for nonce := uint64(0); nonce < 3; nonce++ {
		_, raw := signedTransfer(t, key, nonce)
		if _, e := node.pool(raw, nil, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	clock.Advance(1_000_000_000)
	node.ProduceBlock()
	if c := node.FinalityCounts(); c.Included != 3 || c.Finalized != 0 {
		t.Fatalf("counts %+v", c)
	}
	clock.Advance(2_000_000_000)
	if c := node.FinalityCounts(); c.Finalized != 3 {
		t.Fatalf("counts after lag %+v", c)
	}
	if times := node.FinalizationTimes(); len(times) != 3 {
		t.Fatalf("finalization times %v", times)
	}
}
