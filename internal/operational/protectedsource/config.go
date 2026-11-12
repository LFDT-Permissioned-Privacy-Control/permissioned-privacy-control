package protectedsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	m "privacy-proxy/internal/activitymethoddata"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/disclosuresanctions"
	"privacy-proxy/internal/disclosurewallet"
	"privacy-proxy/internal/explorerquery"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/operational/activitysource"
	"privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/explorerindex"
	"privacy-proxy/internal/policybundle"
)

type Config struct {
	Snapshot      *policybundle.CatalogSnapshot
	Network       d.NetworkBinding
	Index         *explorerindex.Reader
	ExpectedIndex explorerquery.Metadata
	Namespace     *admissionsql.NamespaceReader
	Nodes         map[string]NodeConfig
	Wallet        disclosurewallet.Config
	Finance       admissionsql.FinanceReaderConfig
	Activity      *activitysql.Reader
	Clock         identity.Clock
	RenderKeys    d.Keys
}

// Sources borrows already restricted operational readers. It owns no database
// migration, policy projection, user directory or persistent cursor registry.
type Sources struct {
	plan              d.SourcePlan
	index             *explorerindex.Reader
	indexMetadata     explorerquery.Metadata
	namespace         *admissionsql.NamespaceReader
	namespaceMetadata admissionsql.NamespaceMetadata
	nodes             map[string]NodeConfig
	wallet            *disclosurewallet.Reader
	finance           *admissionsql.FinanceReader
	activity          *activitysource.RetainedPart
	sanctions         *disclosuresanctions.Projector
	sanctionsDigest   d.Digest
	clock             identity.Clock
	render            d.Keys
}

func nilValue(v any) bool {
	if v == nil {
		return true
	}
	x := reflect.ValueOf(v)
	switch x.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		return x.IsNil()
	}
	return false
}
func digestParts(domain string, parts ...any) d.Digest {
	raw, _ := json.Marshal(parts)
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(raw)
	return d.Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}
func digestArray(value [32]byte) d.Digest { return d.Digest("sha256:" + hex.EncodeToString(value[:])) }

func New(ctx context.Context, c Config) (*Sources, error) {
	if ctx == nil || c.Snapshot == nil || c.Index == nil || c.Namespace == nil || c.Activity == nil || c.Clock == nil || c.Index.Metadata() != c.ExpectedIndex || !c.ExpectedIndex.Identity.Valid() || !c.ExpectedIndex.Binding.Valid() || c.ExpectedIndex.Binding.Network != c.Network {
		return nil, d.ErrInvalid
	}
	network, err := c.Network.Key()
	if err != nil {
		return nil, d.ErrInvalid
	}
	meta := c.Snapshot.Metadata()
	if !c.Snapshot.DisclosureConsumerEnabled() {
		return nil, d.ErrInvalid
	}
	if meta.Environment != c.Network.Environment || meta.ChainID != c.Network.ChainID {
		return nil, d.ErrInvalid
	}
	catalog, ok := c.Snapshot.Disclosure()
	if !ok {
		return nil, d.ErrInvalid
	}
	compliance, ok := c.Snapshot.Compliance()
	if !ok {
		return nil, d.ErrUnsupported
	}
	namespace, err := c.Namespace.Metadata(ctx)
	if err != nil {
		return nil, namespaceError(err)
	}
	if !namespace.Ready || [32]byte(namespace.Network) != network {
		return nil, d.ErrInvalid
	}
	organizations := []string{}
	for _, id := range catalog.RuleIDs() {
		rule, _ := catalog.Rule(id)
		organizations = append(organizations, rule.Source().DataOrganizationID)
	}
	slices.Sort(organizations)
	organizations = slices.Compact(organizations)
	if len(organizations) == 0 || len(organizations) != len(c.Nodes) {
		return nil, d.ErrInvalid
	}
	nodes := make(map[string]NodeConfig, len(organizations))
	selected := make([]any, 0, len(organizations))
	for _, organization := range organizations {
		config, ok := c.Nodes[organization]
		if !ok || nilValue(config.Transport) || config.Source.Organization != organization || [32]byte(config.Source.Network.Key) != network || config.Source.Network.Environment != c.Network.Environment || config.Source.Network.ChainID != c.Network.ChainID || config.Source.Network.Genesis.Hex() != c.Network.GenesisHash || config.Source.Network.Deployment != c.Network.DeploymentID || config.Source.PragueStart > namespace.Era.EntryTimestamp || config.Source.PragueEnd < namespace.Era.EndTimestampExclusive {
			return nil, d.ErrInvalid
		}
		if _, err := newNodeRead(config); err != nil {
			return nil, err
		}
		nodes[organization] = config
		selected = append(selected, config.Source)
	}
	activity := c.Activity.Metadata()
	if [32]byte(activity.NetworkKey) != network {
		return nil, d.ErrInvalid
	}
	render, err := d.CopyKeys(c.RenderKeys)
	if err != nil {
		return nil, err
	}
	renderGeneration, err := d.RenderGeneration(render)
	if err != nil {
		return nil, err
	}
	// This is a selected assembly digest, not a database restoration marker.
	plan := d.SourcePlan{Version: 2, Profile: d.RetainedSourceProfile, BundleDigest: d.Digest(meta.ManifestDigest), NetworkKey: digestArray(network), Resources: []p.Resource{p.ActivityLogs, p.ActivitySummary, p.AddressHistory, p.ComplianceReport, p.SanctionsReport, p.Transactions}}
	plan.PlanDigest = digestParts("ops.disclosure.retained-assembly/v1", plan.BundleDigest, plan.NetworkKey, c.ExpectedIndex.Binding, namespace.Era, namespace.State.Generation, selected, c.Wallet.Binding, c.Wallet.ExpectedState, c.Finance.Network, c.Finance.ExpectedState, activity, m.ClassifierDigest(), m.RequestPredicateDigest(), renderGeneration, compliance.Digest())
	c.Wallet.Plan = plan
	c.Finance.Plan = plan
	c.Wallet.Clock = c.Clock
	c.Finance.Clock = c.Clock
	wallet, err := disclosurewallet.NewRetained(c.Wallet)
	if err != nil {
		return nil, err
	}
	finance, err := admissionsql.NewRetainedFinanceReader(c.Finance)
	if err != nil {
		return nil, err
	}
	part, err := activitysource.NewRetainedPart(c.Activity, plan)
	if err != nil {
		return nil, err
	}
	sanctions, err := disclosuresanctions.New(c.Snapshot)
	if err != nil {
		return nil, err
	}
	if now := c.Clock().UTC(); now.IsZero() || now.Unix() < 0 || now.Unix() > p.MaxUnixSeconds {
		return nil, d.ErrInvalid
	}
	return &Sources{plan: plan, index: c.Index, indexMetadata: c.ExpectedIndex, namespace: c.Namespace, namespaceMetadata: namespace, nodes: nodes, wallet: wallet, finance: finance, activity: part, sanctions: sanctions, sanctionsDigest: d.Digest(compliance.Digest()), clock: c.Clock, render: render}, nil
}
func (s *Sources) Plan() d.SourcePlan {
	if s == nil {
		return d.SourcePlan{}
	}
	plan := s.plan
	plan.Resources = slices.Clone(plan.Resources)
	return plan
}

func (s *Sources) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }
