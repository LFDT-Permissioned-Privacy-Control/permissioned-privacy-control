package brokerpolicy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
)

func multiCatalog(t *testing.T) *identity.Catalog {
	t.Helper()
	c, e := identity.Compile(f.MultiIdentitySource(t), allGroups{}, identity.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestMultiSourceIsExplicitAndOwnsDetachedPinnedBytes(t *testing.T) {
	s := f.MultiBrokerSource()
	docs := []brokerpolicy.DocumentBytes{{URL: f.PrivadoContextURL, RawBytes: append([]byte(nil), f.PrivadoContext...)}}
	c, e := brokerpolicy.CompileV2(s, multiCatalog(t), docs)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := c.SourceV1(); ok || c.Source().APIVersion != "" {
		t.Fatal("multi source projected as v1")
	}
	if v, ok := c.MultiSource(); !ok || v.APIVersion != brokerpolicy.MultiAPIVersion {
		t.Fatal("wrong source variant")
	}
	docs[0].RawBytes[0] = 'x'
	d := c.PinnedDocuments()
	d[0].RawBytes[0] = 'x'
	if c.PinnedDocuments()[0].RawBytes[0] != '{' {
		t.Fatal("pinned document escaped")
	}
	s.AzureProfiles = []brokerpolicy.AzureBinding{}
	if _, e := brokerpolicy.CompileV2(s, multiCatalog(t), []brokerpolicy.DocumentBytes{{URL: f.PrivadoContextURL, RawBytes: f.PrivadoContext}}); e != nil {
		t.Fatal("Privado-only source rejected", e)
	}
}
func TestMultiSourceRejectsUnapprovedDestinationsAndVersionAmbiguity(t *testing.T) {
	for name, change := range map[string]func(*brokerpolicy.SourceV2){"old version": func(s *brokerpolicy.SourceV2) { s.APIVersion = brokerpolicy.APIVersion }, "no explicit profile": func(s *brokerpolicy.SourceV2) { s.PrivadoProfiles = nil }, "Azure selected as Privado": func(s *brokerpolicy.SourceV2) { s.PrivadoProfiles[0].ProfileID = f.HumanProfile }, "duplicate profile": func(s *brokerpolicy.SourceV2) { s.PrivadoProfiles = append(s.PrivadoProfiles, s.PrivadoProfiles[0]) }, "extra network": func(s *brokerpolicy.SourceV2) { s.PrivadoNetworks = append(s.PrivadoNetworks, s.PrivadoNetworks[0]) }, "wrong state contract": func(s *brokerpolicy.SourceV2) {
		s.PrivadoNetworks[0].StateContract = "0x2222222222222222222222222222222222222222"
	}, "credential header": func(s *brokerpolicy.SourceV2) {
		s.PrivadoNetworks[0].Credential = &brokerpolicy.RPCCredentialRef{FromEnv: "OPS_BROKER_PRIVADO_TEST", Header: "Cookie"}
	}, "literal credential": func(s *brokerpolicy.SourceV2) {
		s.PrivadoNetworks[0].Credential = &brokerpolicy.RPCCredentialRef{FromEnv: "literal", Header: "Authorization"}
	}, "leading zero chain": func(s *brokerpolicy.SourceV2) { s.PrivadoNetworks[0].ChainID = "080001" }, "HTTP": func(s *brokerpolicy.SourceV2) { s.PrivadoNetworks[0].RPCURL = "http://state.test/rpc" }, "context hash": func(s *brokerpolicy.SourceV2) { s.PinnedDocuments[0].SHA256 = "sha256:" + strings.Repeat("0", 64) }} {
		t.Run(name, func(t *testing.T) {
			s := f.MultiBrokerSource()
			change(&s)
			if _, e := brokerpolicy.CompileV2(s, multiCatalog(t), []brokerpolicy.DocumentBytes{{URL: f.PrivadoContextURL, RawBytes: f.PrivadoContext}}); e == nil {
				t.Fatal("invalid selected source accepted")
			}
		})
	}
	raw, _ := json.Marshal(f.MultiBrokerSource())
	if _, e := brokerpolicy.Decode(raw); e == nil {
		t.Fatal("v1 decoder accepted multi source")
	}
	for _, bad := range []string{strings.Replace(string(raw), `"kind":`, `"Kind":`, 1), strings.TrimSuffix(string(raw), "}") + `,"privadoProfiles":[]}`, string(raw) + "{}"} {
		if _, e := brokerpolicy.DecodeV2([]byte(bad)); e == nil {
			t.Fatal("nonclosed multi source accepted")
		}
	}
}
