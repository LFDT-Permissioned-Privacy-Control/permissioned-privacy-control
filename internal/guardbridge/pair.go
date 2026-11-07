// Package guardbridge pairs a startup-owned Guard preflight service and its
// exact supplemental node binding. It does not authorize, queue or broadcast.
package guardbridge

import (
	"context"
	"errors"
	"net/http"
	"time"

	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
)

type Pair struct {
	service *nodeapproval.Service
	client  *rpcexecution.Client
	timeout time.Duration
}

type QualifiedPrepared struct {
	prepared  *nodeapproval.Prepared // request-local; later delivery is a separate contract.
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
	return &QualifiedPrepared{prepared: prepared, execution: execution, binding: p.client.Metadata()}, nil
}
