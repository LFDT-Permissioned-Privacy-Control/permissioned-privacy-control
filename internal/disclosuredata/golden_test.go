package disclosuredata

import (
	"bytes"
	"encoding/json"
	p "privacy-proxy/internal/disclosurepolicy"
	"strings"
	"testing"
	"time"
)

func TestIndependentSourceRenderAndQueryGoldens(t *testing.T) {
	var qv struct {
		Version   uint8       `json:"v"`
		Resource  p.Resource  `json:"resource"`
		View      View        `json:"view"`
		Targets   []string    `json:"targetActorIds"`
		Addresses p.Addresses `json:"addresses"`
		Time      p.Interval  `json:"dataTime"`
		Level     p.Level     `json:"level"`
	}
	if e := json.Unmarshal([]byte("{\"v\":1,\"resource\":\"activity_summary\",\"view\":\"report\",\"targetActorIds\":[\"ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE\"],\"addresses\":{\"mode\":\"all-target-addresses\",\"values\":[]},\"dataTime\":{\"start\":1790812800,\"end\":1793491199},\"level\":\"redacted\"}"), &qv); e != nil {
		t.Fatal(e)
	}
	scope := p.Scope{TargetActors: qv.Targets, Resources: []p.Resource{qv.Resource}, Addresses: qv.Addresses, DataTime: qv.Time, Level: qv.Level}
	n, e := Normalize(Query{Version: 1, Resource: qv.Resource, View: qv.View}, scope)
	if e != nil || n.Digest() != Digest("sha256:b09cf298c91ff1567dbbd6fcf8e659b9cacdf992a24f28418bc475403b7cbd98") {
		t.Fatal("independent query vector", n.Digest(), e)
	}
	keys := Keys{Active: Key{ID: "render-test", Bytes: bytes.Repeat([]byte{0x33}, 32)}}
	g, e := RenderGeneration(keys)
	if e != nil || g != Digest("sha256:7709e8d0cbbeb9ed5425c740182f71314050c01928d26b9107210b6efcf460b6") {
		t.Fatal("generation vector", g, e)
	}
	keys.Active.Bytes = bytes.Repeat([]byte{0x34}, 32)
	changed, e := RenderGeneration(keys)
	if e != nil || changed != Digest("sha256:874b80884d6abd1937bb67a1bd2d42d95d96bb6b9fea82c8835ac211ec4e917f") || g == changed {
		t.Fatal("same-ID replacement key material binding", changed, e)
	}
	descriptors := []SourceDescriptor{{Version: 1, Kind: ActivitySource, Reference: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NetworkKey: "sha256:308c17e9717958e307cf48c146ecedfe1f51e7e3e712b3cc57ab53fe8b27d44a", Epoch: "sha256:0201792b6eb3575dbb43095d8182ef20df59b4c27d6c7ec7bb0d9bdb342c2674", Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", FormatDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", CoverageDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Population: "RECORDED_RPC_COMPLETIONS_AS_OF_VECTOR", AsOf: time.Unix(1900000000, 0).UTC()}}
	set, e := SourceSetDigest(descriptors, p.ActivitySummary, Report)
	if e != nil || set != Digest("sha256:0d87822535896ce0583cc5229dd3ffabdc3c61643af260a8df61f000ed6c6851") {
		t.Fatal("source set vector", set, e)
	}
	descriptors[0].AsOf = descriptors[0].AsOf.Add(time.Second)
	later, e := SourceSetDigest(descriptors, p.ActivitySummary, Report)
	if e != nil || set != later {
		t.Fatal("volatile source observation invalidated stable cut", e)
	}
}

func TestIndependentStrongNamespaceLocatorAndRenderContext(t *testing.T) {
	network := NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "test-deployment"}
	key, e := network.Key()
	if e != nil {
		t.Fatal(e)
	}
	strong, e := StrongNamespace("sha256:1111111111111111111111111111111111111111111111111111111111111111", key)
	if e != nil || strong != Digest("sha256:0201792b6eb3575dbb43095d8182ef20df59b4c27d6c7ec7bb0d9bdb342c2674") {
		t.Fatal("strong namespace", strong, e)
	}
	rc := RenderContext{Namespace: strong, CaseID: "11111111-1111-4111-8111-111111111111", DataOrganizationID: "22222222-2222-4222-8222-222222222222", RecipientActorID: "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAk", Keys: Keys{Active: Key{ID: "render-test", Bytes: bytes.Repeat([]byte{0x33}, 32)}}}
	rc.Query.scope.Level = p.Redacted
	got := locator(rc.Keys.Active, rc, testAddress(0x11))
	if got != "da1.render-test.3AVmeb8xFDUr-vAhQHJYIg" {
		t.Fatal("independent address ID", got)
	}
	rd, e := RenderContextDigest(rc)
	if e != nil || rd != Digest("sha256:5591641195fcf73618ede38a3f46b7dc784d5d36320d49490aa804cc012fbd60") {
		t.Fatal("render context", rd, e)
	}
}
