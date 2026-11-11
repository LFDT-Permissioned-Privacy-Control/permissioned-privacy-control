package rpcexecution

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"net/http/httptest"
	"testing"
)

func TestClientTraceAccessorOnlyOriginalUnsignedChild(t *testing.T) {
	n := baseNode()
	server := httptest.NewServer(n)
	defer server.Close()
	c := selectedLifecycleClient(t, server.Client().Transport, server.URL, SimulationCallProfileID)
	block, _ := ParseBlockSelector(nil)
	e, err := c.AcquireSimulationCall(t.Context(), testCall(t), block, func(common.Address) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	original := e.RawEvidence()
	trace, err := e.CallTraceJSON()
	if err != nil || !bytes.Contains(trace, []byte(`"output":"0xcafe"`)) || bytes.Contains(trace, []byte("prestateTracer")) || bytes.Contains(trace, []byte("callTracer")) {
		t.Fatal("not child only", string(trace), err)
	}
	trace[0] = '!'
	again, err := e.CallTraceJSON()
	if err != nil || again[0] != '{' || !bytes.Equal(original, e.RawEvidence()) {
		t.Fatal("detached mutation changed source")
	}
	e.signed = true
	if _, err = e.CallTraceJSON(); err == nil {
		t.Fatal("signed evidence became client trace")
	}
	e.signed = false
	legacy, err := acquire(t, baseNode(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.CallTraceJSON(); err == nil {
		t.Fatal("unsupported old profile accessor")
	}
}
