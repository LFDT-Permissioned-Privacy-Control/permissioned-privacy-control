package disclosuredata

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
)

func TestCursorStableSourceIdentityAndMaterialBoundGeneration(t *testing.T) {
	s, ds, f, rc := testFixture(t, p.ActivityLogs, List, p.Full)
	generation, _ := RenderGeneration(rc.Keys)
	binding := CursorBinding{Namespace: s.Namespace, CaseID: s.CaseID, CaseVersion: s.CaseVersion, RecipientActorID: s.RecipientActorID, BundleDigest: s.BundleDigest, RuleDigest: s.RuleDigest, QueryDigest: s.Query.Digest(), RenderGeneration: generation, SourcePlanDigest: ds[0].PlanDigest}
	set, _ := SourceSetDigest(ds, s.Query.resource, s.Query.view)
	refs, _ := SourceReferences(ds)
	pos := Position{Kind: ActivitySource, Activity: &ActivityPosition{f.Activities[0].ObservedAt.UnixMicro(), f.Activities[0].ProducerID, f.Activities[0].RunID, f.Activities[0].CompletionOrdinal, f.Activities[0].ID}}
	oldKey := Key{ID: "old", Bytes: bytes.Repeat([]byte{0x44}, 32)}
	ring, e := NewCursor(Keys{Active: oldKey})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := ring.Seal(binding, set, refs, pos, rc.PreparedAt.Add(time.Minute))
	if e != nil || len(raw) > 2048 {
		t.Fatal(e)
	}
	got, e := ring.Open(raw, binding, rc.PreparedAt)
	if e != nil || got.VerifySourceSet(set) != nil {
		t.Fatal(e)
	}
	detached := got.References()
	detached[0].ID = testDigest(99)
	if got.References()[0].ID == testDigest(99) {
		t.Fatal("mutable continuation ref")
	}
	p2 := got.Position()
	p2.Activity.CompletionOrdinal = "99"
	if got.Position().Activity.CompletionOrdinal == "99" {
		t.Fatal("mutable continuation position")
	}
	ds[0].AsOf = ds[0].AsOf.Add(time.Second)
	later, _ := SourceSetDigest(ds, s.Query.resource, s.Query.view)
	if e := got.VerifySourceSet(later); e != nil {
		t.Fatal("later observation broke unchanged source cut", e)
	}
	ds[0].Generation = "99999999-9999-4999-8999-999999999999"
	changed, _ := SourceSetDigest(ds, s.Query.resource, s.Query.view)
	if !errors.Is(got.VerifySourceSet(changed), ErrConflict) {
		t.Fatal("changed generation did not invalidate continuation")
	}
	changedKeys := rc.Keys
	changedKeys.Active.Bytes = bytes.Repeat([]byte{0x34}, 32)
	changedGen, _ := RenderGeneration(changedKeys)
	different := binding
	different.RenderGeneration = changedGen
	if _, e := ring.Open(raw, different, rc.PreparedAt); !errors.Is(e, ErrConflict) {
		t.Fatal("same ID/material replacement accepted old aliases", e)
	}
	for _, change := range []func(*CursorBinding){func(b *CursorBinding) { b.RecipientActorID = testActor(8) }, func(b *CursorBinding) { b.Namespace = testDigest(99) }, func(b *CursorBinding) { b.CaseVersion++ }, func(b *CursorBinding) { b.RuleDigest = testDigest(90) }, func(b *CursorBinding) { b.QueryDigest = testDigest(91) }, func(b *CursorBinding) { b.SourcePlanDigest = testDigest(92) }} {
		bad := binding
		change(&bad)
		if _, e := ring.Open(raw, bad, rc.PreparedAt); !errors.Is(e, ErrConflict) {
			t.Fatal("bound context changed", e)
		}
	}
	if _, e := ring.Open(raw, binding, rc.PreparedAt.Add(time.Minute)); e == nil {
		t.Fatal("expiry endpoint accepted")
	}
	if _, e := ring.Open(raw+"=", binding, rc.PreparedAt); e == nil {
		t.Fatal("noncanonical base64 accepted")
	}
	rotated, e := NewCursor(Keys{Active: Key{ID: "new", Bytes: bytes.Repeat([]byte{0x55}, 32)}, Previous: &oldKey})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := rotated.Open(raw, binding, rc.PreparedAt); e != nil {
		t.Fatal("encryption-key overlap", e)
	}
	if _, e := ring.Open(strings.Replace(raw, "dd1.", "dc1.", 1), binding, rc.PreparedAt); e == nil {
		t.Fatal("admin cursor purpose accepted")
	}
}
