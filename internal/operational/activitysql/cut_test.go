package activitysql

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit"
)

func TestPinnedFormat2AndCutGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("../../activitylog/testdata/wire-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		CanonicalEnvelope, Content, Predecessor, RowHash, SourceID, SourceRef, Epoch, Coverage, EmptyRef, EmptyCoverage string
		RowID                                                                                                           int64
		NormalEnvelope                                                                                                  a.Envelope
	}
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("vectors")
	}
	e, err := a.DecodeEnvelope([]byte(v.CanonicalEnvelope))
	if err != nil {
		t.Fatal(err)
	}
	content := audit.AccessLogChainContentV2(v.RowID, e.ActorID, e.Method, e.IP, int(e.Status), int(e.HTTP), time.UnixMicro(e.ObservedMicros).UTC(), e.RecordID, v.CanonicalEnvelope)
	hash := sha256.Sum256([]byte(v.Predecessor + content))
	if content != v.Content || hex.EncodeToString(hash[:]) != v.RowHash {
		t.Fatal("existing verifier format2 bytes changed")
	}
	net, _ := a.ParseDigestHex(e.Network)
	configuration, _ := a.ParseDigestHex(e.Configuration)
	state := sourceState{metadata: a.StoreMetadata{NetworkKey: net, SourceID: v.SourceID, Generation: e.Generation, Configuration: configuration, Format: a.Format()}}
	full := makeCut(state, v.RowID, v.RowHash, time.Unix(1, 0))
	if full.Reference != v.SourceRef || full.Epoch != v.Epoch || full.Coverage != v.Coverage {
		t.Fatal(full)
	}
	empty := makeCut(state, 0, "", time.Unix(2, 0))
	if empty.Reference != v.EmptyRef || empty.Coverage != v.EmptyCoverage {
		t.Fatal("head0 must hash EMPTY bytes", empty)
	}
	state.floor = 123
	later := makeCut(state, v.RowID, v.RowHash, time.Unix(100, 0))
	if later.Reference != full.Reference || later.Epoch != full.Epoch || later.Coverage != full.Coverage {
		t.Fatal("observation/floor leaked into stable cut")
	}
}
