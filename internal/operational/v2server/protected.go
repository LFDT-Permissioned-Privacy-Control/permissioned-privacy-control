package v2server

import (
	"context"
	"encoding/hex"
	"time"

	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliancehttp"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/disclosurecase"
	"privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/disclosurehttp"
	"privacy-proxy/internal/disclosurewallet"
	"privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/disclosuresql"
	"privacy-proxy/internal/operational/protectedsource"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/walletops"
)

type Key struct {
	ID      string `json:"id"`
	FromEnv string `json:"fromEnv"`
}
type KeyRing struct {
	Active   Key  `json:"active"`
	Previous *Key `json:"previous,omitempty" optional:"true"`
}
type Era struct {
	EntryNumber           uint64 `json:"entryNumber"`
	EntryHash             string `json:"entryHash"`
	EntryTimestamp        uint64 `json:"entryTimestamp"`
	EndTimestampExclusive uint64 `json:"endTimestampExclusive"`
}
type ProtectedNode struct {
	OrganizationID string   `json:"organizationId"`
	Endpoint       Endpoint `json:"endpoint"`
}
type Protected struct {
	AppDSNEnv       string          `json:"appDSNEnv"`
	StoreEpoch      string          `json:"storeEpoch"`
	NamespaceDSNEnv string          `json:"namespaceDSNEnv"`
	NamespaceEra    Era             `json:"namespaceEra"`
	Nodes           []ProtectedNode `json:"nodes"`
	AdminCursorKeys KeyRing         `json:"adminCursorKeys"`
	RenderKeys      KeyRing         `json:"renderKeys"`
	DataCursorKeys  KeyRing         `json:"dataCursorKeys"`
}

func dataKeys(r KeyRing) (disclosuredata.Keys, error) {
	one := func(k Key) (disclosuredata.Key, error) {
		b, e := binarySecret(k.FromEnv, 32)
		return disclosuredata.Key{ID: k.ID, Bytes: b}, e
	}
	active, e := one(r.Active)
	if e != nil {
		return disclosuredata.Keys{}, e
	}
	out := disclosuredata.Keys{Active: active}
	if r.Previous != nil {
		previous, e := one(*r.Previous)
		if e != nil {
			return out, e
		}
		out.Previous = &previous
	}
	return out, nil
}
func adminKeys(r KeyRing) (disclosurecase.CursorKeys, error) {
	v, e := dataKeys(r)
	if e != nil {
		return disclosurecase.CursorKeys{}, e
	}
	out := disclosurecase.CursorKeys{Active: disclosurecase.CursorKey{ID: v.Active.ID, Key: v.Active.Bytes}}
	if v.Previous != nil {
		out.Previous = &disclosurecase.CursorKey{ID: v.Previous.ID, Key: v.Previous.Bytes}
	}
	return out, nil
}
func modelEra(c Era) (historynamespace.ModelEra, error) {
	var era historynamespace.ModelEra
	if len(c.EntryHash) != 66 || c.EntryHash[:2] != "0x" {
		return era, ErrInvalid
	}
	raw, e := hex.DecodeString(c.EntryHash[2:])
	if e != nil || hex.EncodeToString(raw) != c.EntryHash[2:] {
		return era, ErrInvalid
	}
	copy(era.EntryHash[:], raw)
	era.EntryNumber = c.EntryNumber
	era.EntryTimestamp = c.EntryTimestamp
	era.EndTimestampExclusive = c.EndTimestampExclusive
	if !era.Valid() {
		return era, ErrInvalid
	}
	return era, nil
}

func (s *Server) mountProtected(ctx context.Context, p *dataPlane, wb walletops.ServiceBinding, ws walletops.ExpectedState) error {
	c := s.config.Protected
	era, e := modelEra(c.NamespaceEra)
	if e != nil {
		return e
	}
	dsn, e := secret(c.NamespaceDSNEnv)
	if e != nil {
		return e
	}
	namespace, e := admissionsql.OpenNamespaceReader(ctx, dsn, admission.NetworkBinding(p.network), p.admissionState.Generation, era)
	if e != nil {
		return e
	}
	s.close = append(s.close, namespace.Close)
	s.readyChecks = append(s.readyChecks, namespace.CheckReady)
	nodes := map[string]protectedsource.NodeConfig{}
	for _, n := range c.Nodes {
		if _, exists := nodes[n.OrganizationID]; exists {
			return ErrInvalid
		}
		cr, ref, e := endpointCredential(n.Endpoint.Credential)
		if e != nil {
			return e
		}
		source := creationfacts.Source{Network: p.reference.Network, Organization: n.OrganizationID, URL: n.Endpoint.URL, CredentialRef: ref, CredentialHeader: cr.Header, Profile: "reth-prague-included-creations/v1", PragueStart: n.Endpoint.PragueStart, PragueEnd: n.Endpoint.PragueEnd}
		nodes[n.OrganizationID] = protectedsource.NodeConfig{Source: source, Credential: cr, Transport: p.transport}
		readyClient, e := rpcexecution.NewMetadataClient(p.transport, rpcexecution.MetadataSource{Network: p.network, URL: n.Endpoint.URL, CredentialRef: ref, CredentialHeader: cr.Header, AllowUnauthenticated: ref == ""}, cr, rpcexecution.DefaultMetadataLimits())
		if e != nil {
			return e
		}
		s.addReadyNode(readyClient, cr, true)
	}
	render, e := dataKeys(c.RenderKeys)
	if e != nil {
		return e
	}
	sources, e := protectedsource.New(ctx, protectedsource.Config{Snapshot: s.core, RenderKeys: render, Network: p.network, Index: p.index, ExpectedIndex: p.index.Metadata(), Namespace: namespace, Nodes: nodes, Wallet: disclosurewallet.Config{Store: p.walletReader, Binding: wb, ExpectedState: ws}, Finance: admissionsql.FinanceReaderConfig{Store: p.admissionReader, Network: admission.NetworkBinding(p.network), ExpectedState: p.admissionState}, Activity: p.activityReader, Clock: time.Now})
	if e != nil {
		return e
	}
	dsn, e = secret(c.AppDSNEnv)
	if e != nil {
		return e
	}
	store, e := disclosuresql.Open(ctx, dsn)
	if e != nil {
		return e
	}
	s.close = append(s.close, store.Close)
	s.readyChecks = append(s.readyChecks, store.CheckReady)
	admin, e := adminKeys(c.AdminCursorKeys)
	if e != nil {
		return e
	}
	cursors, e := dataKeys(c.DataCursorKeys)
	if e != nil {
		return e
	}
	cases, e := disclosurecase.NewWithRetainedData(disclosurecase.Config{Snapshot: s.core, Clock: time.Now, Store: store, StoreEpoch: c.StoreEpoch, CursorKeys: admin}, disclosurecase.RetainedDataConfig{Network: p.network, Sources: sources, RenderKeys: render, CursorKeys: cursors})
	if e != nil {
		return e
	}
	handler, e := disclosurehttp.NewWithData(cases)
	if e != nil {
		return e
	}
	handler.Register(s.handler)
	financial, e := compliancehttp.New(p.financial)
	if e != nil {
		return e
	}
	financial.Register(s.handler)
	return nil
}
