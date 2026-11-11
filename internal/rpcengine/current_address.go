package rpcengine

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

type NativeAddressLimits struct {
	Timeout                time.Duration
	MaxAddresses, MaxBytes int
}

func DefaultNativeAddressLimits() NativeAddressLimits {
	return NativeAddressLimits{20 * time.Second, 64, 256 << 10}
}
func (l NativeAddressLimits) valid() bool {
	d := DefaultNativeAddressLimits()
	return l.Timeout > 0 && l.Timeout <= d.Timeout && l.MaxAddresses > 0 && l.MaxAddresses <= d.MaxAddresses && l.MaxBytes > 0 && l.MaxBytes <= d.MaxBytes
}

type nativeAddressSource struct {
	reader   creationfacts.CurrentAddressReader
	metadata creationfacts.AddressReaderMetadata
	limits   NativeAddressLimits
	shared   map[common.Address]bool
}

// nativeOperationFence owns the original deadline and original parent, never a
// canceled acquisition child. Disk recording is synchronous and may finish
// later; elapsed time still withholds its protected result.
type nativeOperationFence struct {
	deadline time.Time
	parent   context.Context
}

func (f *nativeOperationFence) live() bool {
	return f != nil && f.parent != nil && f.parent.Err() == nil && time.Now().Before(f.deadline)
}
func (f *nativeOperationFence) context(caller context.Context) (context.Context, context.CancelFunc, error) {
	if caller == nil || !f.live() {
		return nil, nil, errOperation
	}
	ctx, cancel := context.WithDeadline(caller, f.deadline)
	stop := context.AfterFunc(f.parent, cancel)
	return ctx, func() { stop(); cancel() }, nil
}
func (e *Engine) startNative(ctx context.Context, result *OperationResult) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errOperation
	}
	if e == nil || e.current == nil {
		return ctx, func() {}, nil
	}
	d := time.Now().Add(e.current.limits.Timeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(d) {
		d = parent
	}
	f := &nativeOperationFence{d, ctx}
	child, cancel, err := f.context(ctx)
	if err == nil && result != nil {
		result.fence = f
	}
	return child, cancel, err
}

type nativeAddressPass struct {
	owner          *Engine
	view           *runtimepolicy.View
	passes         []*creationfacts.AddressAssociations
	seen           map[common.Address]bool
	stamp          creationfacts.AddressReadStamp
	head           creationfacts.Header
	bytes          int
	executionHead  creationfacts.Header
	runtimeSamples map[common.Address]rpcexecution.CodeInfo
}

func (e *Engine) currentPass(view *runtimepolicy.View) *nativeAddressPass {
	if e.current == nil {
		return nil
	}
	return &nativeAddressPass{owner: e, view: view, seen: map[common.Address]bool{}}
}

func (p *nativeAddressPass) lookup(ctx context.Context, address common.Address) error {
	return p.lookupNeeded(ctx, address, false)
}
func (p *nativeAddressPass) lookupNeeded(ctx context.Context, address common.Address, association bool) error {
	if p == nil {
		return nil
	}
	if p.owner == nil || p.owner.current == nil || p.view == nil || ctx.Err() != nil || p.view.RequireLive() != nil {
		return errOperation
	}
	if p.seen[address] {
		return nil
	}
	source := p.owner.current
	// Static registry permission and qualified shared infrastructure do not
	// need an unrelated dynamic source read. Pin/code checks still run later.
	_, member, associated, registered := p.view.ContractAssociation(address)
	runtime, _ := p.view.Runtime()
	if source.shared[address] || registered && (!association || member && (associated || !runtime.IntraOrgGrantTracing())) {
		return nil
	}
	if len(p.passes) >= source.limits.MaxAddresses {
		return errOperation
	}
	pass, err := source.reader.ReadAddressAssociations(ctx, address)
	if err != nil || pass == nil || pass.ValidateFor(source.metadata.Identity, source.metadata.Binding, address) != nil || pass.CandidateBytes() > source.limits.MaxBytes-p.bytes {
		return errOperation
	}
	stamp, head := pass.ObservationStamp(), pass.ObserverHead()
	if len(p.passes) == 0 {
		p.stamp = stamp
		p.head = head
	} else {
		if p.stamp != stamp || head.Number == p.head.Number && head.Hash != p.head.Hash {
			return errOperation
		}
		if head.Number > p.head.Number {
			p.head = head
		}
	}
	p.seen[address], p.bytes = true, p.bytes+pass.CandidateBytes()
	p.passes = append(p.passes, pass)
	return nil
}

func (p *nativeAddressPass) engine() (*nativeadmission.Engine, error) {
	if p == nil || p.owner == nil || p.owner.current == nil {
		return nil, errOperation
	}
	m := p.owner.current.metadata
	return p.owner.native.WithCurrentAddressFacts(p.view, m, m.Binding, p.passes)
}
func (p *nativeAddressPass) selectOrg(ctx context.Context, explicit string, address common.Address) (string, bool, error) {
	if p == nil {
		return "", false, errOperation
	}
	if explicit != "" {
		if _, mapped := p.view.Org(explicit); !mapped {
			return "", false, nil
		}
	}
	if err := p.lookup(ctx, address); err != nil {
		return "", false, err
	}
	n, err := p.engine()
	if err != nil {
		return "", false, err
	}
	owner, err := n.CurrentOwner(p.view, address)
	if err != nil {
		return "", false, err
	}
	if explicit != "" {
		return explicit, owner == "" || owner == explicit, nil
	}
	if owner != "" {
		_, member := p.view.Org(owner)
		return owner, member, nil
	}
	ids := p.view.OrgIDs()
	if len(ids) == 1 {
		return ids[0], true, nil
	}
	return "", false, nil
}

// collect visits only relevant indexed execution contexts. It does not scan
// prestate accounts or repeat point queries for repeated frames. Fresh runtime
// namespaces stay in the existing lifecycle materializer, not persisted A3.
func (p *nativeAddressPass) collect(ctx context.Context, e *rpcexecution.CallExecution) error {
	if e == nil {
		return errOperation
	}
	return p.collectEvidence(ctx, e, nil)
}
func (p *nativeAddressPass) collectMined(ctx context.Context, e *rpcexecution.MinedExecution) error {
	return p.collectEvidence(ctx, e, e)
}
func (p *nativeAddressPass) collectEvidence(ctx context.Context, e nativeExecutionEvidence, mined *rpcexecution.MinedExecution) error {
	if p == nil {
		return nil
	}
	if e == nil || e.Tree() == nil {
		return errOperation
	}
	p.runtimeSamples = map[common.Address]rpcexecution.CodeInfo{}
	defer func() { p.runtimeSamples = nil }() // No actual bytecode retained across Append.
	visit := func(i int, a common.Address, caller bool) error {
		code, ok := e.RuntimeCodeAt(i, a)
		if !ok {
			return errOperation
		}
		if _, created := code.CreationRecordIndex(); created || code.Precompile() || caller && !code.HasCode() {
			return nil
		}
		if err := p.lookup(ctx, a); err != nil {
			return err
		}
		return p.rememberRuntime(a, code)
	}
	records := e.Tree().Records()
	for i, r := range records {
		if ctx.Err() != nil || p.view.RequireLive() != nil {
			return errOperation
		}
		if c, creation := e.CreationContext(i); creation {
			if c.Address.Known {
				if err := p.lookup(ctx, c.Address.Value); err != nil {
					return err
				}
			}
		} else if r.Kind == executionfacts.SelfDestruct {
			if !r.To.Known {
				return errOperation
			}
			if err := visit(i, r.To.Value, false); err != nil {
				return err
			}
		} else {
			if r.NominalCodeAddress.Known {
				if err := visit(i, r.NominalCodeAddress.Value, false); err != nil {
					return err
				}
			}
			if r.StorageAddress.Known {
				if err := visit(i, r.StorageAddress.Value, false); err != nil {
					return err
				}
			}
			code, known := e.FrameCode(i)
			if !known {
				return errOperation
			}
			if code.HasCode() && !code.Precompile() {
				if r.NominalCodeAddress.Known {
					if err := p.rememberRuntime(r.NominalCodeAddress.Value, code); err != nil {
						return err
					}
				}
				if target, recognized, err := policycore.InspectUpgradeTarget(r.Input); recognized && err == nil {
					if err := visit(i, target, false); err != nil {
						return err
					}
				}
			}
		}
		if r.CallerAddress.Known {
			if err := visit(i, r.CallerAddress.Value, true); err != nil {
				return err
			}
		}
	}
	// Only cross-owner borrowed code and SELF beneficiaries need the original
	// contract-association gate. Ordinary statically registered CALL targets
	// must not gain an unnecessary SQL dependency merely lacking a read grant.
	n, err := p.engine()
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.Kind == executionfacts.SelfDestruct && r.To.Known {
			if err := p.lookupNeeded(ctx, r.To.Value, true); err != nil {
				return err
			}
		} else if r.NominalCodeAddress.Known && r.StorageAddress.Known && r.NominalCodeAddress.Value != r.StorageAddress.Value {
			codeOwner, _ := n.CurrentOwner(p.view, r.NominalCodeAddress.Value)
			storageOwner, _ := n.CurrentOwner(p.view, r.StorageAddress.Value)
			if codeOwner != "" && codeOwner != storageOwner {
				if err := p.lookupNeeded(ctx, r.NominalCodeAddress.Value, true); err != nil {
					return err
				}
			}
		}
	}
	n, err = p.engine()
	if err != nil {
		return err
	}
	for address, code := range p.runtimeSamples {
		var used bool
		var err error
		if mined != nil {
			used, err = n.ValidateMinedRuntime(p.view, address, code, mined)
		} else {
			used, err = n.ValidateCurrentRuntime(p.view, address, code, e.Anchor())
		}
		if err != nil {
			return err
		}
		if used {
			anchor := e.Anchor()
			p.executionHead = creationfacts.Header{Number: anchor.Number, Hash: anchor.Hash}
		}
	}
	return nil
}

func (p *nativeAddressPass) rememberRuntime(address common.Address, code rpcexecution.CodeInfo) error {
	_, _, _, registered := p.view.ContractAssociation(address)
	if registered || !p.seen[address] || !code.HasCode() || code.Precompile() {
		return nil
	}
	if _, fresh := code.CreationRecordIndex(); fresh {
		return nil
	}
	if old, ok := p.runtimeSamples[address]; ok && (old.Hash() != code.Hash() || old.Length() != code.Length()) {
		return errOperation
	}
	p.runtimeSamples[address] = code
	return nil
}

func (p *nativeAddressPass) requireExecution(ctx context.Context, client *rpcexecution.Client) error {
	if p == nil || p.executionHead == (creationfacts.Header{}) {
		return nil
	}
	if client == nil || client.RequireCanonicalAncestor(ctx, p.executionHead) != nil || ctx.Err() != nil || p.view.RequireLive() != nil {
		return errOperation
	}
	return nil
}

func (p *nativeAddressPass) recheck(ctx context.Context, e *Engine) error {
	if p == nil || p.owner != e || e.current == nil || p.view == nil || ctx.Err() != nil || p.view.RequireLive() != nil {
		return errOperation
	}
	for _, pass := range p.passes {
		if err := e.current.reader.RecheckAddressAssociations(ctx, pass); err != nil {
			return err
		}
	}
	return nil
}

func (p *nativeAddressPass) requireCall(ctx context.Context, e *Engine, client *rpcexecution.Client) error {
	if p == nil || client == nil || p.recheck(ctx, e) != nil {
		return errOperation
	}
	if client.RequireBoundNetwork(ctx) != nil {
		return errOperation
	}
	if p.head != (creationfacts.Header{}) && client.RequireCanonicalAncestor(ctx, p.head) != nil {
		return errOperation
	}
	if p.executionHead != p.head && p.requireExecution(ctx, client) != nil {
		return errOperation
	}
	if ctx.Err() != nil || p.view.RequireLive() != nil {
		return errOperation
	}
	return nil
}
