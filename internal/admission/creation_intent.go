package admission

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/strictjson"
)

const MaxCreationRefsPerBranch = 8

// CreationLimits are availability ceilings, not policy authority. Deployments
// may lower them; compiled upper bounds cannot be raised through an endpoint.
type CreationLimits struct {
	Work, Plans, Bytes, WalletRefs, FactoryRefs int64
}

func DefaultCreationLimits() CreationLimits {
	return CreationLimits{Work: 100000, Plans: 200000, Bytes: 1 << 30, WalletRefs: 800000, FactoryRefs: 800000}
}

func (l CreationLimits) Valid() bool {
	m := DefaultCreationLimits()
	return l.Work > 0 && l.Work <= m.Work && l.Plans > 0 && l.Plans <= m.Plans && l.Bytes > 0 && l.Bytes <= m.Bytes && l.WalletRefs > 0 && l.WalletRefs <= m.WalletRefs && l.FactoryRefs > 0 && l.FactoryRefs <= m.FactoryRefs
}

// CreationIntentStore is an explicit cold-checked schema capability. A legacy
// Store or RawTx implementation does not silently activate intent recording.
type CreationIntentStore interface {
	Store
	CreationIntentSchemaVersion() int
}

type CreationRawTx interface {
	RawTx
	GetWitness(Digest) (Witness, bool, error)
	PutCreationIntent(CreationIntent) (CreationIntentReceipt, error)
}

type CreationWalletAuthority struct {
	Actor, Organization string
	Witness             Digest
}

// CreationIntent is trusted service output after the opaque native approval
// matches. No public HTTP caller can submit these fields as policy authority.
type CreationIntent struct {
	Plan       []byte
	PlanDigest Digest
	Anchor     rpcexecution.Anchor
	Wallet     *CreationWalletAuthority
	Factory    bool
	CapturedAt time.Time
}

type CreationIntentReceipt struct{ Seeds Digest }

func (i CreationIntent) SeedDigest(kind string) Digest {
	parts := [][]byte{i.PlanDigest[:], []byte(kind), i.Anchor.Hash[:], []byte(strconv.FormatUint(i.Anchor.Number, 10)), []byte(strconv.FormatUint(i.Anchor.Timestamp, 10)), []byte(i.Anchor.Profile)}
	if kind == "WALLET" && i.Wallet != nil {
		parts = append(parts, []byte(i.Wallet.Actor), []byte(i.Wallet.Organization), i.Wallet.Witness[:])
	}
	// Observation/decision/wallet timestamps and audit IDs are deliberately not
	// part of retry identity. The found wallet witness retains its first source.
	return HashParts("ops-creation-authority/v1", parts...)
}

func CreationSeedSet(wallet, factory *Digest) Digest {
	parts := [][]byte{}
	if wallet != nil {
		parts = append(parts, []byte("WALLET"), wallet[:])
	}
	if factory != nil {
		parts = append(parts, []byte("FACTORY"), factory[:])
	}
	return HashParts("ops-creation-seed-set/v1", parts...)
}

// DecodeCreationPlan validates present rows and restored rows identically. It
// validates intent shape and identity; it never claims actual chain inclusion.
func DecodeCreationPlan(raw []byte, digest Digest) (nativeadmission.CreationPlanData, error) {
	return decodeCreationPlan(raw, digest, false)
}
func DecodeCapturedCreationPlan(raw []byte, digest Digest) (nativeadmission.CreationPlanData, error) {
	return decodeCreationPlan(raw, digest, true)
}
func decodeCreationPlan(raw []byte, digest Digest, captured bool) (nativeadmission.CreationPlanData, error) {
	var p nativeadmission.CreationPlanData
	if len(raw) == 0 || len(raw) > nativeadmission.MaxCreationPlanBytes {
		return p, ErrInvalid
	}
	wantDigest := nativeadmission.CreationPlanDigest(raw)
	version := nativeadmission.CreationPlanVersion
	if captured {
		wantDigest = nativeadmission.CapturedCreationPlanDigest(raw)
		version = nativeadmission.CapturedCreationPlanVersion
	}
	if len(raw) == 0 || len(raw) > nativeadmission.MaxCreationPlanBytes || wantDigest != common.Hash(digest) {
		return p, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, 12)
	if err != nil {
		return p, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF || strictjson.ExactDecode(v, &p) != nil {
		return p, ErrInvalid
	}
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, raw) || p.Version != version || (!captured && p.CaptureProfile != "") || (captured && p.CaptureProfile != creationfacts.CaptureProfile) || p.Hash == (common.Hash{}) || !ValidUUID(p.RootOrg) || len(p.Entries) < 1 || len(p.Entries) > nativeadmission.MaxCreationEntries || p.Entries == nil || p.Declarations == nil || p.FactoryRoots == nil {
		return p, ErrInvalid
	}
	if _, err := ParseDigest(p.Manifest); err != nil {
		return p, ErrInvalid
	}
	if _, err := ParseDigest(p.Runtime); err != nil {
		return p, ErrInvalid
	}
	chain, err := ParseUint256(p.Chain, true)
	if err != nil || !chain.IsUint64() || (p.Evidence != rpcexecution.LifecycleSignedProfileID && p.Evidence != rpcexecution.LifecycleGuardProfileID) || len(p.Declarations) > policybundle.MaxCreationFactories || len(p.FactoryRoots) > len(p.Entries) {
		return p, ErrInvalid
	}
	seen := map[common.Address]bool{}
	for _, f := range p.Declarations {
		a, err := ParseAddress(f.Address)
		if err != nil || f.Address != AddressString(a) || a == (common.Address{}) || seen[a] || policycore.IsPraguePrecompile(a) || !ValidUUID(f.OrganizationID) || f.Scope != policybundle.FactoryCreationSubtree || len(f.CodeHash) != 66 || f.CodeHash != strings.ToLower(f.CodeHash) {
			return p, ErrInvalid
		}
		h, err := hex.DecodeString(strings.TrimPrefix(f.CodeHash, "0x"))
		if err != nil || !strings.HasPrefix(f.CodeHash, "0x") || len(h) != 32 || common.BytesToHash(h) == (common.Hash{}) {
			return p, ErrInvalid
		}
		seen[a] = true
	}
	usedDeclarations := make([]bool, len(p.Declarations))
	usedRoots := make([]bool, len(p.FactoryRoots))
	lastRecord := -1
	for j, e := range p.Entries {
		n, ok := new(big.Int).SetString(strings.TrimPrefix(e.Value, "0x"), 16)
		if !ok || n.Sign() < 0 || n.BitLen() > 256 || e.Value != "0x"+n.Text(16) || !ValidUUID(e.Namespace) || e.InputHash == (common.Hash{}) || (e.Kind != "CREATE" && e.Kind != "CREATE2") || e.Depth < 0 || e.Depth > 256 || e.Record <= lastRecord || e.Record >= 4096 || e.CreationParent < -1 || e.CreationParent >= j || e.FactoryRoot < -1 || e.FactoryRoot >= len(p.FactoryRoots) {
			return p, ErrInvalid
		}
		if e.CreationParent >= 0 && p.Entries[e.CreationParent].Depth >= e.Depth {
			return p, ErrInvalid
		}
		lastRecord = e.Record
		if e.FactoryRoot >= 0 {
			r := p.FactoryRoots[e.FactoryRoot]
			if r.Entry < 0 || r.Entry > j || r.Declaration < 0 || r.Declaration >= len(p.Declarations) {
				return p, ErrInvalid
			}
			f := p.Declarations[r.Declaration]
			if f.OrganizationID != e.Namespace || p.Entries[r.Entry].Creator != common.HexToAddress(f.Address) || p.Entries[r.Entry].FactoryRoot != e.FactoryRoot {
				return p, ErrInvalid
			}
			ancestor := j
			for ancestor >= 0 && ancestor != r.Entry {
				ancestor = p.Entries[ancestor].CreationParent
			}
			if ancestor != r.Entry {
				return p, ErrInvalid
			}
			usedDeclarations[r.Declaration], usedRoots[e.FactoryRoot] = true, true
		}
	}
	for _, used := range usedDeclarations {
		if !used {
			return p, ErrInvalid
		}
	}
	for _, used := range usedRoots {
		if !used {
			return p, ErrInvalid
		}
	}
	return p, nil
}

// PlanData validates a stored observation envelope, not a caller's permission.
// A factory has no ActorID; recovery must not invent one to decode its facts.
func (i CreationIntent) PlanData() (nativeadmission.CreationPlanData, error) {
	return i.planData(false)
}
func (i CreationIntent) CapturedPlanData() (nativeadmission.CreationPlanData, error) {
	return i.planData(true)
}
func (i CreationIntent) planData(captured bool) (nativeadmission.CreationPlanData, error) {
	p, err := decodeCreationPlan(i.Plan, i.PlanDigest, captured)
	if err != nil || i.CapturedAt.IsZero() || i.CapturedAt.Unix() < 0 || i.CapturedAt.Unix() > 253402300799 || i.Anchor.Hash == (common.Hash{}) || i.Anchor.ChainID != p.Chain || i.Anchor.OrganizationID != p.RootOrg || i.Anchor.Profile != p.Evidence || (!i.Factory && i.Wallet == nil) || (i.Factory && len(p.FactoryRoots) == 0) {
		return p, ErrInvalid
	}
	if i.Wallet != nil && (!validActor(i.Wallet.Actor) || !ValidUUID(i.Wallet.Organization) || i.Wallet.Witness == (Digest{})) {
		return p, ErrInvalid
	}
	return p, nil
}
func (i CreationIntent) Validate(scope Scope) (nativeadmission.CreationPlanData, error) {
	return i.validate(scope, false)
}
func (i CreationIntent) ValidateCaptured(scope Scope) (nativeadmission.CreationPlanData, error) {
	return i.validate(scope, true)
}
func (i CreationIntent) validate(scope Scope, captured bool) (nativeadmission.CreationPlanData, error) {
	p, err := i.planData(captured)
	if err != nil || !scope.Valid() || p.Hash != scope.Hash || p.RootOrg != scope.Organization {
		return p, ErrInvalid
	}
	if i.Wallet != nil && (i.Wallet.Actor != scope.Actor || i.Wallet.Organization != scope.Organization) {
		return p, ErrInvalid
	}
	return p, nil
}
