package historyfacts

import (
	"context"
	"crypto/sha256"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/readprivacyabi"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

type Config struct {
	Snapshot      *policybundle.CatalogSnapshot
	Clock         identity.Clock
	Network       networkidentity.Binding
	Wallets       *walletadapter.Resolver
	WalletBinding walletops.ServiceBinding
	WalletState   walletops.ExpectedState
	Shares        ShareReader
	ShareExpected ShareBinding
	Timeout       time.Duration
	MaxBytes      int
}
type Factory struct {
	config        Config
	views         *runtimepolicy.Factory
	shareIdentity *ReaderIdentity
	profile       readprivacy.ReadProfile
}

func New(c Config) (*Factory, error) {
	if c.Timeout == 0 {
		c.Timeout = MaxOperationTime
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = MaxChargedBytes
	}
	if c.Snapshot == nil || c.Clock == nil || c.Wallets == nil || c.Timeout <= 0 || c.Timeout > MaxOperationTime || c.MaxBytes <= 0 || c.MaxBytes > MaxChargedBytes || !c.WalletState.Valid() {
		return nil, ErrInvalid
	}
	if _, err := c.Network.Key(); err != nil {
		return nil, ErrInvalid
	}
	w := c.WalletBinding
	if w.Environment != c.Network.Environment || w.ChainID != c.Network.ChainID || w.GenesisHash != c.Network.GenesisHash || w.DeploymentID != c.Network.DeploymentID {
		return nil, ErrInvalid
	}
	ns, err := w.Namespace()
	if err != nil {
		return nil, ErrInvalid
	}
	m := c.Wallets.Metadata()
	if m.Namespace != ns || m.ExpectedState != c.WalletState {
		return nil, ErrInvalid
	}
	metadata := c.Snapshot.Metadata()
	if metadata.Profile != policybundle.RuntimeCreationObservedProfileID || metadata.Environment != c.Network.Environment || metadata.ChainID != c.Network.ChainID {
		return nil, ErrInvalid
	}
	runtime, ok := c.Snapshot.Runtime()
	if !ok {
		return nil, ErrInvalid
	}
	profile, err := readprivacy.ParseReadProfile(runtime.ReadProfile())
	if err != nil {
		return nil, ErrInvalid
	}
	var shareIdentity *ReaderIdentity
	if c.Shares == nil {
		if !profile.Strict() {
			return nil, ErrInvalid
		}
	} else {
		if !c.ShareExpected.Valid() || c.ShareExpected.Network != c.Network {
			return nil, ErrInvalid
		}
		sm := c.Shares.Metadata()
		if sm.Binding != c.ShareExpected || sm.Mode != "reader" || !sm.Identity.Valid() {
			return nil, ErrInvalid
		}
		shareIdentity = sm.Identity
	}
	views, err := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if err != nil {
		return nil, ErrInvalid
	}
	return &Factory{c, views, shareIdentity, profile}, nil
}

// UsesSnapshot allows an owning engine to reject a differently selected catalog
// before any source I/O. Metadata equality alone is not snapshot identity.
func (f *Factory) UsesSnapshot(s *policybundle.CatalogSnapshot) bool {
	return f != nil && f.config.Snapshot == s
}

type Current struct {
	owner                   *Factory
	view                    *runtimepolicy.View
	org, method, credential string
	wallet                  nativeadmission.WalletSnapshot
	shares                  *SharePass
	authDigest              [32]byte
	fence                   Fence
	charged                 int
}

// Begin verifies the original JWT once and checks the exact selected method
// scope before loading operational wallets. It neither chooses a default bank
// nor accepts a caller-constructed principal. Anonymous reads are a separate
// serving-engine decision; this constructor requires a verified bearer.
func (f *Factory) Begin(ctx context.Context, rawJWT, selectedOrg, method string) (*Current, error) {
	if f == nil {
		return nil, ErrInvalid
	}
	fence, err := NewFence(ctx, f.config.Timeout)
	if err != nil {
		return nil, err
	}
	view, err := f.views.Build(rawJWT)
	if err != nil {
		return nil, ErrUnavailable
	}
	org, ok := view.Org(selectedOrg)
	if !ok || !org.GroupAllowsMethod(method) {
		return nil, ErrUnavailable
	}
	declaration, ok := f.config.Snapshot.Method(method)
	if !ok {
		return nil, ErrUnavailable
	}
	for _, claim := range declaration.RequiredClaims {
		mask := map[string]uint8{"admin": policycore.ClaimAdmin, "deploy": policycore.ClaimDeploy, "upgrade": policycore.ClaimUpgrade}[claim]
		if mask == 0 || org.UnionClaims()&mask == 0 {
			return nil, ErrUnavailable
		}
	}
	credential, err := org.SelectCredentialRef(method)
	if err != nil {
		return nil, ErrUnavailable
	}
	bound, cancel, err := fence.Bind(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	wallet, err := f.config.Wallets.Load(bound, view.ActorID())
	if err != nil {
		return nil, ErrUnavailable
	}
	charged := 1024 + 32*len(wallet.Addresses())
	if charged > f.config.MaxBytes {
		return nil, ErrTooBroad
	}
	if bound.Err() != nil || fence.Check() != nil || view.RequireLive() != nil {
		return nil, ErrUnavailable
	}
	return &Current{owner: f, view: view, org: selectedOrg, method: method, credential: credential, wallet: wallet, authDigest: sha256.Sum256([]byte(rawJWT)), fence: fence, charged: charged}, nil
}
func (c *Current) OriginalView() *runtimepolicy.View {
	if c == nil {
		return nil
	}
	return c.view
}
func (c *Current) Organization() string {
	if c == nil {
		return ""
	}
	return c.org
}
func (c *Current) Method() string {
	if c == nil {
		return ""
	}
	return c.method
}
func (c *Current) CredentialRef() string {
	if c == nil {
		return ""
	}
	return c.credential
}
func (c *Current) AuthCapture() [32]byte {
	if c == nil {
		return [32]byte{}
	}
	return c.authDigest
}
func (c *Current) WalletVersion() string {
	if c == nil {
		return ""
	}
	return c.wallet.Version()
}
func (c *Current) OwnAddresses() []common.Address {
	if c == nil {
		return nil
	}
	return c.wallet.Addresses()
}
func (c *Current) Profile() readprivacy.ReadProfile {
	if c == nil || c.owner == nil {
		return readprivacy.ReadProfileUnset
	}
	return c.owner.profile
}
func (c *Current) ChargedBytes() int {
	if c == nil {
		return 0
	}
	return c.charged
}
func (c *Current) Bind(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if c == nil || c.owner == nil || c.view == nil || c.view.RequireLive() != nil {
		return nil, nil, ErrUnavailable
	}
	return c.fence.Bind(ctx)
}

// WithShares returns a new immutable context. It is called only once, after
// bounded candidate acquisition and outside any other database transaction.
func (c *Current) WithShares(ctx context.Context, hashes []common.Hash) (*Current, error) {
	if c == nil || c.owner == nil || c.shares != nil {
		return nil, ErrInvalid
	}
	bound, cancel, err := c.Bind(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if c.Profile().Strict() {
		next := *c
		return &next, nil
	}
	remaining := c.owner.config.MaxBytes - c.charged
	if remaining <= 0 || len(hashes) > MaxShareHashes || 256+64*len(hashes) > remaining {
		return nil, ErrTooBroad
	}
	q, err := PrepareShareQuery(hashes, c.fence, remaining)
	if err != nil {
		return nil, err
	}
	m := c.owner.config.Shares.Metadata()
	if m.Identity != c.owner.shareIdentity || m.Binding != c.owner.config.ShareExpected || m.Mode != "reader" {
		return nil, ErrUnavailable
	}
	pass, err := c.owner.config.Shares.Read(bound, q)
	if err != nil {
		return nil, err
	}
	if pass.ValidateFor(c.owner.shareIdentity, c.owner.config.ShareExpected) != nil || !slices.Equal(pass.Query().Hashes, q.Hashes) {
		return nil, ErrUnavailable
	}
	if c.charged+pass.ChargedBytes() > c.owner.config.MaxBytes {
		return nil, ErrTooBroad
	}
	if bound.Err() != nil || c.fence.Check() != nil || c.view.RequireLive() != nil {
		return nil, ErrUnavailable
	}
	next := *c
	next.shares = pass
	next.charged += pass.ChargedBytes()
	return &next, nil
}

func (c *Current) Listed(hash common.Hash) bool {
	if c == nil || c.Profile().Strict() || c.shares == nil {
		return false
	}
	s, ok := c.shares.Share(hash)
	return ok && slices.Contains(s.Recipients, c.view.ActorID())
}

// Address is plain address visibility, never an emitter grant. A selected-org
// mismatch cannot borrow another organization's current contract association.
func (c *Current) Address(address common.Address) explorerdata.AddressVisibility {
	v := explorerdata.AddressVisibility{Address: walletops.AddressString(address), Level: explorerdata.VisibilityHidden, Reason: explorerdata.ReasonNoAccess}
	if c == nil || c.owner == nil || c.view == nil {
		return v
	}
	if c.wallet.Contains(address) {
		v.Visible = true
		v.Level = explorerdata.VisibilityFull
		v.Reason = explorerdata.ReasonOwnAddress
		return v
	}
	if publicProtocolAddress(address) {
		v.Visible = true
		v.Level = explorerdata.VisibilityFull
		v.Reason = explorerdata.ReasonPublicAddress
		return v
	}
	contract, registered := c.view.Contract(address)
	if registered {
		v.Level = explorerdata.VisibilityRedacted
		if contract.OwnerOrg() == c.org && contract.Associated() {
			v.Visible = true
			v.Level = explorerdata.VisibilityFull
			v.Reason = explorerdata.ReasonRBACGroupMember
		}
	}
	return v
}

// Preserve the ordinary V1 public floor. This context has no fork/state
// qualification for later native precompiles. Zero, unknown low addresses and
// absent registry/SQL records are not public.
func publicProtocolAddress(address common.Address) bool {
	for _, b := range address[:19] {
		if b != 0 {
			return false
		}
	}
	return address[19] >= 1 && address[19] <= 9
}

type Emitter struct {
	Registry                                     runtimepolicy.RegistryMetadata
	Registered, HasGrant, Admin, VisibleToUnlock bool
	Rules                                        *readprivacyabi.EventRulesField
}

// Emitter obtains event authority only from the selected owner's current Git
// grants/admin. Own wallets, deployer/state associations, shares and generic
// Full address visibility never create that authority.
func (c *Current) Emitter(address common.Address) Emitter {
	if c == nil || c.owner == nil || c.view == nil {
		return Emitter{}
	}
	contract, registered := c.view.Contract(address)
	if !registered {
		return Emitter{}
	}
	e := Emitter{Registry: contract.RegistryMetadata(), Registered: true}
	if contract.OwnerOrg() != c.org {
		return e
	}
	grants := contract.ReadGrants()
	e.HasGrant = len(grants) > 0 || contract.AdminForRead()
	e.Admin = contract.AdminForRead()
	e.VisibleToUnlock = e.HasGrant && e.Registry.AllowVisibleToUnlock
	for _, grant := range grants {
		r := &readprivacyabi.EventRulesField{Wildcard: grant.EventRules.Mode == "all"}
		for _, rule := range grant.EventRules.Rules {
			x := readprivacyabi.EventRule{Topic0: rule.Topic0, Name: rule.Name}
			for _, p := range rule.ParamRules {
				x.ParamRules = append(x.ParamRules, readprivacyabi.ParamRule{Index: p.Index, MustBe: p.MustBe})
			}
			r.Rules = append(r.Rules, x)
		}
		e.Rules = readprivacyabi.UnionEventRules(e.Rules, r)
	}
	return e
}

// AdminForDataset requires a positively registered owning contract. Selecting
// an org, an unknown native-transfer row or an EOA is not positive attribution.
func (c *Current) AdminForDataset(ownerContract common.Address) bool {
	return !c.Profile().Strict() && c.Emitter(ownerContract).Admin
}

// Recheck is the final fact gate AFTER the actual Recorder append. It performs
// no append or output itself. The serving owner must run it before releasing
// protected bytes, and must still check its own original node/source result.
func (c *Current) Recheck(ctx context.Context) error {
	bound, cancel, err := c.Bind(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	f := c.owner
	if c.shares != nil {
		if m := f.config.Shares.Metadata(); m.Identity != f.shareIdentity || m.Binding != f.config.ShareExpected || m.Mode != "reader" {
			return ErrUnavailable
		}
		if f.config.Shares.Recheck(bound, c.shares) != nil {
			return ErrUnavailable
		}
	}
	wallet, err := f.config.Wallets.Load(bound, c.view.ActorID())
	if err != nil || wallet.Version() != c.wallet.Version() || wallet.ActorID() != c.wallet.ActorID() {
		return ErrUnavailable
	}
	// Same original View after the last SQL/network operation; no re-verification,
	// renewal, replacement principal, or expiry derived from a fresh clock age.
	if bound.Err() != nil || c.fence.Check() != nil || c.view.RequireLive() != nil {
		return ErrUnavailable
	}
	return nil
}
