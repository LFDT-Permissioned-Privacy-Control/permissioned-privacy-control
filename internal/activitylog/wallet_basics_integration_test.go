package activitylog_test

import (
	"crypto/sha256"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	f "privacy-proxy/internal/creationfacts"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcstatepolicy"
)

func walletBasicsConfig(t *testing.T, n *metadataNode, snapshot *policybundle.CatalogSnapshot, clock *atomic.Int64, wallet *d.WalletFixture) (rpcengine.StateConfig, *stateFacts) {
	t.Helper()
	c := stateConfig(t, n, snapshot, clock)
	raw := encoded(t, rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}, LinkedWalletBasics: true})
	var err error
	c.Policy, err = rpcstatepolicy.Compile(raw, rpcstatepolicy.Digest(sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	facts := stateFactsFixture(n, common.HexToAddress(addressA), d.Org, "")
	facts.rows = []f.AddressAssociation{}
	c.Associations, c.AssociationBinding = facts, facts.meta.Binding
	c.Wallets, c.WalletBinding, c.WalletState = wallet.Resolver, wallet.Binding, wallet.State
	return c, facts
}

func TestWalletBasicsActualLinkCurrentOwnerAndPending(t *testing.T) {
	db := rawPostgres(t)
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	fixture := d.DefaultStateFixture(t)
	d.EnableServiceIdentity(t, &fixture)
	snapshot := d.StateSnapshot(t, fixture)
	wallet := d.ActualWalletFixture(t, t.Context(), db.ownerDSN, snapshot, n.network(), func() time.Time { return time.Unix(clock.Load(), 0) })
	token := d.Token(t, snapshot, d.Subject, "Auditor")
	key, _ := crypto.HexToECDSA(strings.Repeat("1", 64))
	target := wallet.Link(t, t.Context(), token, key)
	c, facts := walletBasicsConfig(t, n, snapshot, &clock, wallet)
	engine := stateEngine(t, c)
	for _, method := range []string{"eth_getBalance", "eth_getTransactionCount"} {
		before := n.count()
		r, body := stateQuery(t, engine, []string{"Bearer " + token}, d.Org, method, `["`+target.Hex()+`","pending"]`)
		m, _ := r.MetadataFor(engine)
		if m.Class != rpcengine.SuccessfulCompletion || r.RequireDeliverable(t.Context(), engine) != nil || n.count() != before+4 {
			t.Fatal("actual owned pending basic denied", m, string(body))
		}
		n.mu.Lock()
		call := n.calls[len(n.calls)-2]
		n.mu.Unlock()
		if call.Method != method || string(call.Params[1]) != `"pending"` {
			t.Fatal("pending converted or wrong method", call)
		}
	}
	serviceToken := d.ServiceToken(t, snapshot, d.Subject)
	serviceKey, _ := crypto.HexToECDSA(strings.Repeat("4", 64))
	serviceTarget := wallet.Link(t, t.Context(), serviceToken, serviceKey)
	serviceResult, serviceBody := stateQuery(t, engine, []string{"Bearer " + serviceToken}, d.Org, "eth_getTransactionCount", `["`+serviceTarget.Hex()+`","pending"]`)
	serviceMetadata, _ := serviceResult.MetadataFor(engine)
	if serviceMetadata.Class != rpcengine.SuccessfulCompletion || serviceMetadata.ActorID == d.Actor(d.Subject) || serviceResult.RequireDeliverable(t.Context(), engine) != nil {
		t.Fatal("configured actual workload identity/proof failed", serviceMetadata, string(serviceBody))
	}
	// Original snapshot ownership is rechecked, even when the target remains
	// linked and only another real operational link changes the set/version.
	stale, _ := stateQuery(t, engine, []string{"Bearer " + token}, d.Org, "eth_getBalance", `["`+target.Hex()+`"]`)
	otherKey, _ := crypto.HexToECDSA(strings.Repeat("5", 64))
	wallet.Link(t, t.Context(), token, otherKey)
	if stale.RequireDeliverable(t.Context(), engine) == nil {
		t.Fatal("changed original wallet snapshot accepted")
	}
	for _, roles := range []struct {
		subject        string
		roles          []string
		method, params string
	}{{d.AdminSubject, []string{"Auditor"}, "eth_getBalance", `["` + target.Hex() + `"]`}, {d.Subject, []string{"Unmapped"}, "eth_getBalance", `["` + target.Hex() + `"]`}, {d.Subject, []string{"Auditor"}, "eth_getBalance", `["` + target.Hex() + `","0x1"]`}, {d.Subject, []string{"Auditor"}, "eth_getCode", `["` + target.Hex() + `"]`}, {d.Subject, []string{"Auditor"}, "eth_getProof", `["` + target.Hex() + `",[]]`}, {d.Subject, []string{"Auditor"}, "eth_getStorageAt", `["` + target.Hex() + `","` + stateInfra + `"]`}} {
		before := n.count()
		_, body := stateQuery(t, engine, []string{"Bearer " + d.Token(t, snapshot, roles.subject, roles.roles...)}, d.Org, roles.method, roles.params)
		requireMetadataCode(t, body, -32001)
		if n.count() != before {
			t.Fatal("wallet proof bypassed actor/method/historical gate")
		}
	}
	before := n.count()
	_, body := stateQuery(t, engine, []string{"Bearer " + token}, d.Org, "eth_getBalance", `["`+addressB+`"]`)
	requireMetadataCode(t, body, -32001)
	if n.count() != before {
		t.Fatal("unlinked recipient became public")
	}
	for _, edit := range []func(*rpcengine.StateConfig){func(c *rpcengine.StateConfig) { c.Associations = nil }, func(c *rpcengine.StateConfig) { c.Wallets = nil }, func(c *rpcengine.StateConfig) { c.WalletBinding.ServiceOrigin = "https://other.test" }, func(c *rpcengine.StateConfig) { c.WalletState.Generation = d.OtherOrg }, func(c *rpcengine.StateConfig) { c.WalletBinding.DeploymentID = "other" }} {
		bad := c
		edit(&bad)
		if _, err := rpcengine.NewState(bad); err == nil {
			t.Fatal("foreign/missing wallet/A3 cold binding admitted")
		}
	}
	disabled := c
	disabled.Policy = stateDefinition(t, snapshot, []string{}, []rpcstatepolicy.PreRegisteredAddress{})
	if _, err := rpcengine.NewState(disabled); err == nil {
		t.Fatal("absent/disabled flag accepted injected wallet authority")
	}
	// Current Git permission is independent of both operational sources.
	git := stateReadSnapshot(t, nil)
	gitConfig, gitFacts := walletBasicsConfig(t, n, git, &clock, wallet)
	gitFacts.fail = true
	if _, err := wallet.Owner.Exec(t.Context(), `UPDATE ops_wallet_v2.store_state SET ready=false WHERE namespace=$1`, wallet.Namespace[:]); err != nil {
		t.Fatal(err)
	}
	before = n.count()
	_, body = stateQuery(t, engine, []string{"Bearer " + token}, d.Org, "eth_getBalance", `["`+target.Hex()+`"]`)
	requireMetadataCode(t, body, -32002)
	if n.count() != before {
		t.Fatal("unready ownership source became empty/public")
	}
	gitEngine := stateEngine(t, gitConfig)
	r, body := stateQuery(t, gitEngine, []string{"Bearer " + d.Token(t, git, d.Subject, "Auditor")}, d.Org, "eth_getCode", `["`+addressA+`"]`)
	m, _ := r.MetadataFor(gitEngine)
	if m.Class != rpcengine.SuccessfulCompletion || gitFacts.reads.Load() != 0 || r.RequireDeliverable(t.Context(), gitEngine) != nil {
		t.Fatal("positive Git depended on A3/wallet source", m, string(body))
	}
	a3 := stateFactsFixture(n, target, d.Org, d.Actor(d.Subject))
	a3Config := c
	a3Config.Associations, a3Config.AssociationBinding = a3, a3.meta.Binding
	a3Engine := stateEngine(t, a3Config)
	a3Result, a3Body := stateQuery(t, a3Engine, []string{"Bearer " + token}, d.Org, "eth_getBalance", `["`+target.Hex()+`"]`)
	a3Metadata, _ := a3Result.MetadataFor(a3Engine)
	if a3Metadata.Class != rpcengine.SuccessfulCompletion || a3Result.RequireDeliverable(t.Context(), a3Engine) != nil || a3.reads.Load() != 1 || a3.rechecks.Load() != 1 {
		t.Fatal("existing positive A3 depended on wallet or skipped original gates", a3Metadata, string(a3Body))
	}
	if _, err := wallet.Owner.Exec(t.Context(), `UPDATE ops_wallet_v2.store_state SET ready=true WHERE namespace=$1`, wallet.Namespace[:]); err != nil {
		t.Fatal(err)
	}
	// Foreign dynamic owner must not be overridden by proving an EOA key.
	other := stateFactsFixture(n, target, d.OtherOrg, "")
	c.Associations, c.AssociationBinding = other, other.meta.Binding
	engine = stateEngine(t, c)
	_, body = stateQuery(t, engine, []string{"Bearer " + token}, d.Org, "eth_getBalance", `["`+target.Hex()+`"]`)
	requireMetadataCode(t, body, -32001)
	if facts.reads.Load() == 0 {
		t.Fatal("wallet branch omitted scoped A3 safety read")
	}
}

func TestWalletBasicsActualRevokeWhilePebbleAppendHeld(t *testing.T) {
	db := rawPostgres(t)
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	snapshot := d.StateSnapshot(t, d.DefaultStateFixture(t))
	wallet := d.ActualWalletFixture(t, t.Context(), db.ownerDSN, snapshot, n.network(), func() time.Time { return time.Unix(clock.Load(), 0) })
	token := d.Token(t, snapshot, d.Subject, "Auditor")
	key, _ := crypto.HexToECDSA(strings.Repeat("2", 64))
	target := wallet.Link(t, t.Context(), token, key)
	c, _ := walletBasicsConfig(t, n, snapshot, &clock, wallet)
	engine := stateEngine(t, c)
	x := setupActivityDatabase(t, n.network())
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error { close(entered); <-release; return nil }, engine.OperationBinding().Methods...)
	service, err := rpcactivity.New(rpcactivity.Config{State: engine, Recorder: recorder, Network: n.network()})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := service.Handler(d.Org)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	before := metadataRows(t, x)
	done := requestAsync(t, server.Client(), server.URL, token, string(metadataRequest("eth_getBalance", `["`+target.Hex()+`","pending"]`)), t.Context())
	await(t, entered)
	if _, err := wallet.Service.Unlink(t.Context(), token, target.Hex()); err != nil {
		t.Fatal("actual operational revoke during real Append", err)
	}
	once.Do(func() { close(release) })
	body := bodyResult(t, done)
	requireMetadataCode(t, body, -32002)
	if strings.Contains(string(body), "0x2a") {
		t.Fatal("revoked original wallet permission leaked through Append")
	}
	selected := metadataSealedOne(t, x, before)
	if selected.Outcome != "success" || selected.ActorID != d.Actor(d.Subject) || selected.Method != "eth_getBalance" {
		t.Fatal("wallet revocation replaced selected outcome", selected)
	}
}
