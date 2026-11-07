package activitysql_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit/buffer"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/activitysource"
	s "privacy-proxy/internal/operational/activitysql"
)

func TestActualActivityIPProjectionPreservesOriginalAndRedacts(t *testing.T) {
	x := setupDatabase(t)
	writer, err := s.OpenWriter(t.Context(), x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	run, err := writer.StartRun(t.Context(), a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	entries := []buffer.Entry{}
	for i, ip := range []string{"", "192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"} {
		entry := attributed(t, testEntry(t, run.Binding(), int64(i+1), (f.Now-5+int64(i))*1000000), "eth_call", true)
		record, _ := a.DecodeSpool(entry.Data)
		fields := record.Fields()
		fields.IP = ip
		raw, _ := json.Marshal(fields)
		entry.Data = raw[:len(raw)-len(`,"b":""}`)]
		entry.Data = append(entry.Data, '}')
		if _, err := a.DecodeSpool(entry.Data); err != nil {
			t.Fatal("original IP invalid", ip, err)
		}
		entries = append(entries, entry)
	}
	if err := run.SealBatch(t.Context(), entries); err != nil {
		t.Fatal(err)
	}
	invalid := bytes.ReplaceAll(entries[3].Data, []byte("::ffff:192.0.2.1"), []byte("not-an-IP"))
	if err := run.SealOne(t.Context(), run.Binding().Base+10, invalid); err == nil {
		t.Fatal("invalid IP metadata sealed")
	}
	reader, err := s.OpenReader(t.Context(), x.reader, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	network, _ := x.registration.Network.Key()
	bundle := d.Digest("sha256:" + strings.Repeat("a", 64))
	plan := d.SourcePlan{Version: 1, Profile: "ops.disclosure.data-sources/v1", BundleDigest: bundle, NetworkKey: d.Digest("sha256:" + hex.EncodeToString(network[:])), PlanDigest: d.Digest("sha256:" + strings.Repeat("b", 64)), Resources: []p.Resource{p.ActivityLogs}}
	source, err := activitysource.New(reader, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []p.Level{p.Full, p.Pseudonymous, p.Redacted} {
		original := f.Scope()
		original.Resources = []p.Resource{p.ActivityLogs}
		original.Level = level
		query, err := d.Normalize(d.Query{Version: 1, Resource: p.ActivityLogs, View: d.List}, original)
		if err != nil {
			t.Fatal(err)
		}
		scope := d.ReadScope{Namespace: d.Digest("sha256:" + strings.Repeat("c", 64)), CaseID: uuid.NewString(), CaseVersion: 1, RecipientActorID: f.Actor(f.Subject), DataOrganizationID: f.Org, BundleDigest: bundle, RuleDigest: d.Digest("sha256:" + strings.Repeat("d", 64)), EffectiveUntil: time.Unix(f.Now+1200, 0).UTC(), Query: query}
		snapshot, err := source.Open(t.Context(), scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		facts, err := snapshot.Read(t.Context(), scope, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(facts.Activities) != 4 || facts.Activities[0].TrustedIP != nil || *facts.Activities[3].TrustedIP != "192.0.2.1" {
			t.Fatal("empty/mapped source projection", facts.Activities)
		}
		rc := d.RenderContext{PreparedAt: time.Unix(f.Now, 0).UTC(), Namespace: scope.Namespace, CaseID: scope.CaseID, DataOrganizationID: f.Org, RecipientActorID: scope.RecipientActorID, Keys: d.Keys{Active: d.Key{ID: "render", Bytes: bytes.Repeat([]byte{1}, 32)}}, Query: query, EffectiveUntil: scope.EffectiveUntil}
		result, err := d.Render(scope, snapshot.Descriptors(), facts, rc, uuid.NewString())
		snapshot.Close()
		if err != nil {
			t.Fatal(level, err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("192.0.2.1")) != (level == p.Full) || bytes.Contains(raw, []byte("2001:db8::1")) != (level == p.Full) || bytes.Contains(raw, []byte("::ffff:")) {
			t.Fatal("IP projection/redaction", level, string(raw))
		}
	}
}
