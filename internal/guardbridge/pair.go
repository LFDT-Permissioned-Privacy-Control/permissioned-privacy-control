// Package guardbridge owns paired Guard evidence, delivery and node bindings.
// The caller applies native authorization and commits financial effects before
// enqueueing the original approval or broadcasting signed bytes.
package guardbridge

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
)

type Pair struct {
	service  *nodeapproval.Service
	client   *rpcexecution.Client
	timeout  time.Duration
	delivery bool
}

type QualifiedPrepared struct {
	origin    *Pair
	prepared  *nodeapproval.Prepared // original sealed request-local result; never reconstructed for delivery.
	execution *rpcexecution.CallExecution
	binding   rpcexecution.BindingMetadata
}

func (q *QualifiedPrepared) Execution() *rpcexecution.CallExecution {
	if q == nil {
		return nil
	}
	return q.execution
}
func (q *QualifiedPrepared) Binding() rpcexecution.BindingMetadata {
	if q == nil {
		return rpcexecution.BindingMetadata{}
	}
	return q.binding
}

func NewPair(binding rpcexecution.NodeBinding, credentialRef string, transport http.RoundTripper, hashMode uint8, limits rpcexecution.Limits) (*Pair, error) {
	if binding.Profile != rpcexecution.GuardRetainedProfileID {
		return nil, errors.New("invalid Guard pair configuration")
	}
	owned := make(map[string]rpcexecution.Credential, len(binding.Credentials))
	for k, v := range binding.Credentials {
		owned[k] = v
	}
	binding.Credentials = owned
	client, err := rpcexecution.NewClient(transport, binding, limits)
	if err != nil {
		return nil, errors.New("invalid Guard pair configuration")
	}
	client, err = client.WithCredential(credentialRef)
	if err != nil {
		return nil, errors.New("invalid Guard pair credential")
	}
	credential := binding.Credentials[credentialRef]
	if credentialRef == "" {
		credential = rpcexecution.Credential{}
	}
	service, err := nodeapproval.NewBoundPreflight(nodeapproval.BoundPreflightOptions{URL: binding.URL, Transport: transport, CredentialHeader: credential.Header, CredentialValue: credential.Value, HashMode: hashMode})
	if err != nil {
		return nil, errors.New("Guard pair unavailable")
	}
	return &Pair{service: service, client: client, timeout: limits.AcquisitionTimeout}, nil
}

func (p *Pair) Close() {
	if p != nil && p.service != nil {
		p.service.Close()
	}
}

func (p *Pair) AcquireSigned(ctx context.Context, tx transactioninput.VerifiedTransaction) (*QualifiedPrepared, error) {
	if p == nil || p.service == nil || p.client == nil || !tx.Valid() || (tx.Type() != 0 && tx.Type() != 2) || tx.ChainID() != p.client.Metadata().ChainID {
		return nil, errors.New("invalid Guard transaction")
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	prepared, err := p.service.Prepare(ctx, tx.RawHex())
	if err != nil {
		return nil, errors.New("Guard preflight unavailable")
	}
	return p.qualify(ctx, prepared, tx)
}

func (p *Pair) qualify(ctx context.Context, prepared *nodeapproval.Prepared, tx transactioninput.VerifiedTransaction) (*QualifiedPrepared, error) {
	e, ok := p.service.EvidenceFor(prepared)
	if !ok {
		return nil, errors.New("unqualified Guard evidence")
	}
	execution, err := p.client.QualifyTrustedGuardEvidence(ctx, tx, rpcexecution.TrustedGuardEvidence{Profile: e.Profile(), Calls: e.Calls(), Prestate: e.Prestate(), ChainID: e.ChainID(), TransactionHash: e.TransactionHash(), Fingerprint: e.Fingerprint(), HashMode: e.HashMode(), HeaderHash: e.HeaderHash(), HeaderNumber: e.HeaderNumber(), HeaderTimestamp: e.HeaderTimestamp(), HeaderPresent: true})
	if err != nil {
		return nil, errors.New("unqualified Guard evidence")
	}
	return &QualifiedPrepared{origin: p, prepared: prepared, execution: execution, binding: p.client.Metadata()}, nil
}

// NewDeliveryPair owns the same selected node credential for preflight,
// supplemental evidence and broadcast. Delivery settings never override it.
func NewDeliveryPair(binding rpcexecution.NodeBinding, credentialRef string, transport http.RoundTripper, hashMode uint8, limits rpcexecution.Limits, options nodeapproval.BoundDeliveryOptions) (*Pair, error) {
	if binding.Profile != rpcexecution.GuardRetainedProfileID {
		return nil, errors.New("invalid Guard pair configuration")
	}
	client, err := rpcexecution.NewClient(transport, binding, limits)
	if err != nil {
		return nil, err
	}
	client, err = client.WithCredential(credentialRef)
	if err != nil {
		return nil, err
	}
	credential := binding.Credentials[credentialRef]
	if credentialRef == "" {
		credential = rpcexecution.Credential{}
	}
	options.BoundPreflightOptions = nodeapproval.BoundPreflightOptions{URL: binding.URL, CredentialHeader: credential.Header, CredentialValue: credential.Value, Transport: transport, HashMode: hashMode}
	service, err := nodeapproval.NewBoundDelivery(options)
	if err != nil {
		return nil, err
	}
	return &Pair{service: service, client: client, timeout: limits.AcquisitionTimeout, delivery: true}, nil
}

func (p *Pair) Metadata() rpcexecution.BindingMetadata {
	if p == nil || p.client == nil {
		return rpcexecution.BindingMetadata{}
	}
	return p.client.Metadata()
}

func (p *Pair) Ready() bool {
	if p == nil || p.service == nil || p.client == nil {
		return false
	}
	chain, err := strconv.ParseUint(p.client.Metadata().ChainID, 10, 64)
	return err == nil && p.service.Ready(chain)
}

// EnqueueQualified accepts only this Pair's untouched original request-local
// approval. The caller must first commit and validate its financial receipt.
func (p *Pair) EnqueueQualified(q *QualifiedPrepared) error {
	if p == nil || !p.delivery || p.service == nil || q == nil || q.origin != p || q.prepared == nil {
		return errors.New("unqualified Guard approval")
	}
	if _, ok := p.service.EvidenceFor(q.prepared); !ok {
		return errors.New("unqualified Guard approval")
	}
	return p.service.Enqueue(q.prepared)
}

func (p *Pair) BroadcastRaw(ctx context.Context, tx transactioninput.VerifiedTransaction) (common.Hash, error) {
	if p == nil || p.client == nil {
		return common.Hash{}, errors.New("Guard pair unavailable")
	}
	return p.client.BroadcastRaw(ctx, tx)
}
