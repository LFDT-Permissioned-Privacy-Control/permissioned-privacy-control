package disclosurecase_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/policybundle"
)

type constructorStore struct{ c.Store }
type constructorSources struct{ plan d.SourcePlan }

func (s constructorSources) Plan() d.SourcePlan { return s.plan }
func (s constructorSources) Open(context.Context, d.ReadScope, []d.SourceRef) (d.Snapshot, error) {
	return nil, d.ErrUnavailable
}
func sourceConfig(snapshot *policybundle.CatalogSnapshot) c.DataConfig {
	network := d.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "test"}
	key, _ := network.Key()
	return c.DataConfig{Network: network, Sources: constructorSources{d.SourcePlan{Version: 1, Profile: "ops.disclosure.data-sources/v1", BundleDigest: d.Digest(snapshot.Metadata().ManifestDigest), NetworkKey: d.Digest("sha256:" + strings.ToLower(bytesToHex(key[:]))), PlanDigest: d.Digest("sha256:" + strings.Repeat("a", 64)), Resources: []p.Resource{p.ActivitySummary, p.Transactions}}}, RenderKeys: d.Keys{Active: d.Key{ID: "render", Bytes: bytes.Repeat([]byte{1}, 32)}}, CursorKeys: d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{2}, 32)}}}
}
func bytesToHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = digits[v>>4]
		out[2*i+1] = digits[v&15]
	}
	return string(out)
}
func TestNewDataOnlyKeyAndProfileQualification(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	cfg := c.Config{Snapshot: snapshot, Clock: func() time.Time { return time.Unix(f.Now, 0) }, Store: constructorStore{}, StoreEpoch: "epoch", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{3}, 32)}}}
	dc := sourceConfig(snapshot)
	service, e := c.NewWithData(cfg, dc)
	if e != nil || !service.DataEnabled() {
		t.Fatal(e)
	}
	release, ok := service.TryAdmitHTTP()
	if !ok {
		t.Fatal("admission")
	}
	release()
	release()
	bad := dc
	bad.RenderKeys = d.Keys{}
	if _, e := c.NewWithData(cfg, bad); e == nil {
		t.Fatal("redacted data service accepted no render key")
	}
	bad = dc
	bad.RenderKeys.Active.Bytes = cfg.CursorKeys.Active.Key
	if _, e := c.NewWithData(cfg, bad); e == nil {
		t.Fatal("aliased admin/render key")
	}
	bad = dc
	bad.Network.DeploymentID = "other"
	if _, e := c.NewWithData(cfg, bad); e == nil {
		t.Fatal("network/source plan mismatch")
	}
	if old, e := c.New(cfg); e != nil || old.DataEnabled() {
		t.Fatal("old metadata constructor changed", e)
	}
	rule := f.DefaultRule()
	rule.Resources = []p.Resource{p.Events}
	eventSnapshot := f.Snapshot(t, []p.RuleSource{rule})
	cfg.Snapshot = eventSnapshot
	bad = sourceConfig(eventSnapshot)
	if _, e := c.NewWithData(cfg, bad); !errors.Is(e, d.ErrUnsupported) {
		t.Fatal("staged Events falsely advertised as ready", e)
	}
}
func TestLegacyMetadataIsNotNewExposureReceipt(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	e := c.Event{ID: "11111111-1111-4111-8111-111111111111", CaseID: "22222222-2222-4222-8222-222222222222", Epoch: "epoch", Actor: f.Actor(f.Subject), Action: "exposure_prepared", Outcome: "allowed", RuleID: "auditor", RuleDigest: digest, BundleDigest: digest, AttemptID: "33333333-3333-4333-8333-333333333333", CaseVersion: 1, PreparedAt: time.Unix(f.Now, 0).UTC(), Summary: c.EventSummary{Count: 1, RuleContext: "current"}}
	if c.ValidateEvent(e) != nil {
		t.Fatal("legacy metadata no longer readable")
	}
	if c.ValidateExposureEvent(e) == nil {
		t.Fatal("old action text minted new output receipt")
	}
	e.Summary.Exposure = &c.ExposureSummary{Version: 1, Resource: p.ActivitySummary, View: d.Report, QueryDigest: digest, SourceSetDigest: digest, RenderDigest: digest, OutputDigest: digest, OutputBytes: 20, ReturnedRows: 1}
	if c.ValidateEvent(e) != nil || c.ValidateExposureEvent(e) != nil {
		t.Fatal("closed new exposure rejected")
	}
	e.Actor = "invalid"
	if c.ValidateExposureEvent(e) == nil {
		t.Fatal("dedicated validator skipped common event binding")
	}
}
