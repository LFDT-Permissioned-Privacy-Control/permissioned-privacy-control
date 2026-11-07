package nativeadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

const CreationPlanVersion = "ops-creation-plan/v1"
const CapturedCreationPlanVersion = "ops-creation-plan/v2"
const MaxCreationEntries = 128
const MaxCreationPlanBytes = 64 << 10

var ErrCreationIntent = errors.New("invalid approved creation intent")

// The compact names below belong to the bounded operational encoding, not a
// public configuration API. No input/runtime bytecode or identity claims enter
// this document. FactoryRoot refers to Roots, not a call-tree record ordinal.
type CreationEntry struct {
	Address        common.Address `json:"a"`
	Creator        common.Address `json:"c"`
	Kind           string         `json:"k"`
	Namespace      string         `json:"n"`
	InputHash      common.Hash    `json:"i"`
	Value          string         `json:"v"`
	Caller         common.Address `json:"u"`
	Depth          int            `json:"d"`
	Record         int            `json:"o"`
	CreationParent int            `json:"p"`
	FactoryRoot    int            `json:"f"`
}

type CreationFactoryRoot struct {
	Entry       int `json:"x"`
	Declaration int `json:"d"`
}

type CreationPlanData struct {
	Version        string                            `json:"v"`
	CaptureProfile string                            `json:"q,omitempty" optional:"true"`
	Hash           common.Hash                       `json:"t"`
	RootOrg        string                            `json:"o"`
	Manifest       string                            `json:"m"`
	Runtime        string                            `json:"r"`
	Chain          string                            `json:"c"`
	Evidence       string                            `json:"e"`
	Entries        []CreationEntry                   `json:"x"`
	Declarations   []policybundle.FactoryAttribution `json:"f"`
	FactoryRoots   []CreationFactoryRoot             `json:"z"`
}

// CreationPlan is produced only by a complete successful native pass. The
// exported detached data is an observation intent, never a permission verdict.
type CreationPlan struct {
	data    CreationPlanData
	encoded []byte
	digest  common.Hash
}

func (p *CreationPlan) Data() CreationPlanData {
	if p == nil {
		return CreationPlanData{}
	}
	d := p.data
	d.Entries = slices.Clone(d.Entries)
	d.Declarations = slices.Clone(d.Declarations)
	d.FactoryRoots = slices.Clone(d.FactoryRoots)
	return d
}

func (p *CreationPlan) Encoded() []byte {
	if p == nil {
		return nil
	}
	return bytes.Clone(p.encoded)
}

func (p *CreationPlan) Digest() common.Hash {
	if p == nil {
		return common.Hash{}
	}
	return p.digest
}

func (p *CreationPlan) HasFactoryAuthority() bool {
	return p != nil && len(p.data.FactoryRoots) > 0
}

func CreationPlanDigest(encoded []byte) common.Hash {
	return creationPlanDigest(CreationPlanVersion, encoded)
}
func CapturedCreationPlanDigest(encoded []byte) common.Hash {
	return creationPlanDigest(CapturedCreationPlanVersion, encoded)
}
func creationPlanDigest(version string, encoded []byte) common.Hash {
	h := sha256.New()
	_, _ = h.Write([]byte(version + "\x00"))
	_, _ = h.Write(encoded)
	return common.BytesToHash(h.Sum(nil))
}

type creationCapture struct{ plan *CreationPlan }

// ApprovedSignedCheck binds the exact successful pass to its request objects.
// A caller cannot recreate this capability from the serialized plan or a bool.
type ApprovedSignedCheck struct {
	engine    *Engine
	view      *runtimepolicy.View
	execution *rpcexecution.CallExecution
	org       string
	wallets   WalletSnapshot
	plan      *CreationPlan
}

func (a *ApprovedSignedCheck) Plan() *CreationPlan {
	if a == nil {
		return nil
	}
	return a.plan
}

func (a *ApprovedSignedCheck) RequireMatches(v *runtimepolicy.View, org string, e *rpcexecution.CallExecution, w WalletSnapshot) error {
	if a == nil || a.engine == nil || !a.engine.creationIntents || a.view != v || a.execution != e || a.org != org || v == nil || e == nil || v.RequireLive() != nil || !e.Signed() {
		return ErrCreationIntent
	}
	if a.wallets.valid != w.valid || a.wallets.actorID != w.actorID || a.wallets.version != w.version || !a.wallets.evidenceAt.Equal(w.evidenceAt) || !slices.Equal(a.wallets.addresses, w.addresses) {
		return ErrCreationIntent
	}
	if v.Metadata().ManifestDigest != a.engine.metadata.ManifestDigest || v.Metadata().ChainID != a.engine.metadata.ChainID || e.Anchor().OrganizationID != org {
		return ErrCreationIntent
	}
	return nil
}

func (n *Engine) CheckSignedWithCreationPlan(ctx context.Context, v *runtimepolicy.View, org string, e *rpcexecution.CallExecution, w WalletSnapshot) (*ApprovedSignedCheck, error) {
	if n == nil || !n.creationIntents {
		return nil, ErrCreationIntent
	}
	capture := &creationCapture{}
	decision := n.check(ctx, v, org, e, w, true, capture)
	if !decision.Allowed || ctx.Err() != nil || v.RequireLive() != nil {
		return nil, ErrCreationIntent
	}
	ownedWallets := w
	ownedWallets.addresses = slices.Clone(w.addresses)
	return &ApprovedSignedCheck{engine: n, view: v, execution: e, org: org, wallets: ownedWallets, plan: capture.plan}, nil
}

// captureCreations is called after every native frame and SELF check passed.
// Its scope stack follows ALL routed frames; a foreign CALL can terminate an
// inherited factory scope even when there is no intervening CREATE record.
func (n *Engine) captureCreations(ctx context.Context, v *runtimepolicy.View, org string, e *rpcexecution.CallExecution, records []executionfacts.Record, planned []lifecyclePlan, fresh []bool, work uint64, out *creationCapture) bool {
	count := 0
	var extra uint64
	for i, r := range records {
		extra++
		if fresh[i] {
			count++
			extra += 1 + uint64(len(r.Input)+31)/32
		}
	}
	if count > MaxCreationEntries || extra > MaxAdmissionWork-work {
		return false
	}
	if count == 0 {
		return true
	}
	hash, known := e.TransactionHash()
	if !known {
		return false
	}
	d := CreationPlanData{Version: CreationPlanVersion, Hash: hash, RootOrg: org, Manifest: string(n.metadata.ManifestDigest), Runtime: string(n.runtime.Digest()), Chain: n.metadata.ChainID, Evidence: e.Anchor().Profile,
		Entries: make([]CreationEntry, 0, count), Declarations: []policybundle.FactoryAttribution{}, FactoryRoots: []CreationFactoryRoot{}}
	type activeScope struct {
		root int
		org  string
	}
	scopes := make([]activeScope, len(records))
	nearest := make([]int, len(records))
	declarations := map[common.Address]int{}
	for i, r := range records {
		if ctx.Err() != nil || v.RequireLive() != nil {
			return false
		}
		scope, ancestor := activeScope{root: -1}, -1
		if r.ParentIndex >= 0 {
			if r.ParentIndex >= i {
				return false
			}
			scope, ancestor = scopes[r.ParentIndex], nearest[r.ParentIndex]
		}
		if scope.root >= 0 && scope.org != planned[i].org {
			scope = activeScope{root: -1}
		}
		nearest[i] = ancestor
		if fresh[i] {
			if !r.StorageAddress.Known || !r.CallerAddress.Known || (r.Kind != executionfacts.Create && r.Kind != executionfacts.Create2) {
				return false
			}
			entryIndex := len(d.Entries)
			entry := CreationEntry{Address: r.StorageAddress.Value, Creator: r.From, Kind: string(r.Kind), Namespace: planned[i].org, InputHash: crypto.Keccak256Hash(r.Input), Value: "0x" + r.Value.Text(16), Caller: r.CallerAddress.Value, Depth: r.Depth, Record: i, CreationParent: ancestor, FactoryRoot: scope.root}
			if factory, configured := n.factories[r.From]; configured && factory.OrganizationID == planned[i].org {
				code, ok := e.RuntimeCodeAt(i, r.From)
				if !ok {
					return false
				}
				if code.HasCode() && !code.Precompile() && !code.Delegated() && code.Hash() == common.HexToHash(factory.CodeHash) {
					declaration, found := declarations[r.From]
					if !found {
						declaration = len(d.Declarations)
						declarations[r.From] = declaration
						d.Declarations = append(d.Declarations, factory)
					}
					scope = activeScope{root: len(d.FactoryRoots), org: factory.OrganizationID}
					d.FactoryRoots = append(d.FactoryRoots, CreationFactoryRoot{Entry: entryIndex, Declaration: declaration})
					entry.FactoryRoot = scope.root
				}
			}
			d.Entries = append(d.Entries, entry)
			nearest[i] = entryIndex
		}
		scopes[i] = scope
	}
	if n.creationObserved {
		d.Version = CapturedCreationPlanVersion
		d.CaptureProfile = creationfacts.CaptureProfile
	}
	encoded, err := json.Marshal(d)
	if err != nil || len(encoded) > MaxCreationPlanBytes || ctx.Err() != nil || v.RequireLive() != nil {
		return false
	}
	out.plan = &CreationPlan{data: d, encoded: encoded, digest: creationPlanDigest(d.Version, encoded)}
	return true
}
