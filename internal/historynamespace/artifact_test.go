package historynamespace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const testOrg = "12345678-1234-4234-8234-123456789abc"

func testEra() ModelEra {
	return ModelEra{EntryNumber: 100, EntryHash: Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
}
func finiteInput() map[string]any {
	return map[string]any{"kind": "prague-finite", "address": Address{8}.String(), "runtimeHash": Hash{9}.String(), "runtimeLength": 1,
		"initial": map[string]any{"kind": "org", "organizationId": testOrg}, "physical": map[string]any{"kind": "preexisting"},
		"start": Cut{100, Hash{1}, 0}, "end": Cut{150, Hash{2}, 1}}
}
func checkpointInput(address byte) map[string]any {
	return map[string]any{"kind": "prague-checkpoint", "address": Address{address}.String(), "runtimeHash": Hash{9}.String(), "runtimeLength": 1,
		"initial": map[string]any{"kind": "org", "organizationId": testOrg}, "physical": map[string]any{"kind": "preexisting"},
		"checkpoint": CheckpointRef{150, Hash{2}}}
}
func artifactBytes(t *testing.T, statements ...any) []byte {
	t.Helper()
	v := map[string]any{"apiVersion": ArtifactAPIVersion, "cohortId": testOrg, "modelId": ModelID, "era": testEra(),
		"network":    map[string]any{"environment": "test", "chainId": "80001", "genesisHash": Hash{3}.String(), "deploymentId": "namespace-test"},
		"statements": statements}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestArtifactStableSemanticIdentityAndDetachedValues(t *testing.T) {
	raw := artifactBytes(t, finiteInput())
	a, err := ParseArtifact(raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, raw, "", "  ") != nil {
		t.Fatal("indent")
	}
	other, err := ParseArtifact(pretty.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	d, err := other.Compile(nil)
	if err != nil || c.Digest() != d.Digest() || c.RawDigest() == d.RawDigest() {
		t.Fatalf("raw/semantic identities not separate: %v", err)
	}
	changedID := bytes.Replace(raw, []byte(`"cohortId":"`+testOrg+`"`), []byte(`"cohortId":"12345678-1234-4234-8234-123456789abd"`), 1)
	third, err := ParseArtifact(changedID)
	if err != nil {
		t.Fatal(err)
	}
	e, err := third.Compile(nil)
	if err != nil || c.Digest() != e.Digest() {
		t.Fatal("new submission UUID changed original semantic identity", err)
	}
	lives, ids := c.Lifetimes()
	*lives[0].Initial.OrganizationID = "changed"
	lives[0].Start.Number = 0
	ids[0] = Digest{}
	got, gotIDs := c.Lifetimes()
	if *got[0].Initial.OrganizationID != testOrg || got[0].Start.Number != 100 || gotIDs[0] == (Digest{}) {
		t.Fatal("returned values alias immutable cohort")
	}
}

func TestArtifactRejectsHostileWireAndFalsePhysicalShapes(t *testing.T) {
	base := artifactBytes(t, finiteInput())
	for name, raw := range map[string][]byte{
		"duplicate":       bytes.Replace(base, []byte(`"apiVersion":`), []byte(`"apiVersion":"x","apiVersion":`), 1),
		"case alias":      bytes.Replace(base, []byte(`"apiVersion"`), []byte(`"APIVersion"`), 1),
		"explicit null":   bytes.Replace(base, []byte(`"physical":{"kind":"preexisting"}`), []byte(`"physical":null`), 1),
		"unknown field":   bytes.Replace(base, []byte(`"runtimeLength":1`), []byte(`"runtimeLength":1,"grant":true`), 1),
		"empty statement": artifactBytes(t),
		"trailing":        append(append([]byte{}, base...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseArtifact(raw); err == nil {
				t.Fatal("accepted malformed source")
			}
		})
	}
	for name, change := range map[string]func(map[string]any){
		"born without coordinate": func(v map[string]any) { v["physical"] = map[string]any{"kind": "born"} },
		"preexisting with birth": func(v map[string]any) {
			v["physical"] = map[string]any{"kind": "preexisting", "birth": BirthCoordinate{100, Hash{1}, Hash{3}, 0, 0}}
		},
		"born not yet runtime": func(v map[string]any) {
			v["physical"] = map[string]any{"kind": "born", "birth": BirthCoordinate{100, Hash{1}, Hash{3}, 0, 0}}
		},
		"in-era with UUID": func(v map[string]any) { v["lifetimeId"] = testOrg },
		"straddles entry":  func(v map[string]any) { v["start"] = Cut{99, Hash{4}, 0} },
		"empty runtime":    func(v map[string]any) { v["runtimeLength"] = 0 },
		"oversize runtime": func(v map[string]any) { v["runtimeLength"] = MaxRuntimeBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			v := finiteInput()
			change(v)
			if _, err := ParseArtifact(artifactBytes(t, v)); err == nil {
				t.Fatal("accepted false shape")
			}
		})
	}
	deep := []byte(`{"unknown":` + strings.Repeat("[", 20) + `0` + strings.Repeat("]", 20) + `}`)
	if _, err := ParseArtifact(deep); err == nil {
		t.Fatal("deep source accepted")
	}
	if _, err := ParseArtifact(make([]byte, MaxArtifactBytes+1)); err != ErrTooBroad {
		t.Fatal("oversize source", err)
	}
}

func TestCheckpointProofBindingAndClosedCohortShape(t *testing.T) {
	a, err := ParseArtifact(artifactBytes(t, checkpointInput(8), checkpointInput(7)))
	if err != nil {
		t.Fatal(err)
	}
	point, addresses, ok := a.CheckpointRequest()
	if !ok || point.Number != 150 || len(addresses) != 2 || addresses[0] != (Address{7}) {
		t.Fatal("checkpoint request is not deterministic")
	}
	addresses[0] = Address{}
	if _, again, _ := a.CheckpointRequest(); again[0] == (Address{}) {
		t.Fatal("checkpoint request aliases artifact")
	}
	if _, err := a.Compile(nil); err == nil {
		t.Fatal("checkpoint admitted without proof metadata")
	}
	f := CheckpointFacts{Network: a.NetworkKey(), Source: Digest{5}, Era: testEra(), Number: 150, Hash: Hash{2}, Timestamp: 1500,
		Codes: []QualifiedCode{{Address{7}, Hash{9}, 1}, {Address{8}, Hash{9}, 1}}}
	c, err := a.Compile(&f)
	if err != nil {
		t.Fatal(err)
	}
	lives, _ := c.Lifetimes()
	if lives[0].ProofDigest == nil || *lives[0].ProofDigest == (Digest{}) {
		t.Fatal("owned proof metadata was not bound")
	}
	f.Codes[0].RuntimeHash = Hash{4}
	if _, err := a.Compile(&f); err == nil {
		t.Fatal("runtime mismatch accepted")
	}
	if _, err := ParseArtifact(artifactBytes(t, checkpointInput(8), checkpointInput(8))); err == nil {
		t.Fatal("duplicate checkpoint address accepted")
	}
	multi := checkpointInput(9)
	multi["checkpoint"] = CheckpointRef{151, Hash{4}}
	if _, err := ParseArtifact(artifactBytes(t, checkpointInput(8), multi)); err == nil {
		t.Fatal("multiple checkpoint blocks accepted")
	}
	forged := checkpointInput(8)
	forged["proofDigest"] = Digest{7}.String()
	if _, err := ParseArtifact(artifactBytes(t, forged)); err == nil {
		t.Fatal("caller asserted a proof digest")
	}
	statements := make([]any, 129)
	for i := range statements {
		statements[i] = checkpointInput(byte(i))
	}
	if _, err := ParseArtifact(artifactBytes(t, statements...)); err == nil {
		t.Fatal("129 checkpoint addresses accepted")
	}
}

func TestFiniteEraBoundariesAndNoUnexpectedProof(t *testing.T) {
	v := finiteInput()
	v["kind"], v["lifetimeId"], v["start"], v["end"] = "pre-era-finite", testOrg, Cut{90, Hash{3}, 0}, Cut{100, Hash{1}, 0}
	delete(v, "physical")
	a, err := ParseArtifact(artifactBytes(t, v))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Compile(&CheckpointFacts{}); err == nil {
		t.Fatal("unused proof accepted")
	}
	v["end"] = Cut{100, Hash{1}, 1}
	if _, err := ParseArtifact(artifactBytes(t, v)); err == nil {
		t.Fatal("pre-era interval crosses era start")
	}
	v = finiteInput()
	v["physical"] = map[string]any{"kind": "born", "birth": BirthCoordinate{100, Hash{1}, Hash{3}, 0, 0}}
	v["start"] = Cut{100, Hash{1}, 1}
	if _, err := ParseArtifact(artifactBytes(t, v)); err != nil {
		t.Fatal("valid after-birth finite attestation rejected", err)
	}
	for _, raw := range []string{`null`, `"x"`, fmt.Sprint(1)} {
		if _, err := ParseArtifact([]byte(raw)); err == nil {
			t.Fatal("non-object source accepted")
		}
	}
}
