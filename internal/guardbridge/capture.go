package guardbridge

import (
	"context"
	"errors"

	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
)

func (p *Pair) CaptureSource(network creationfacts.Network) (creationfacts.Source, error) {
	if p == nil || !p.lifecycle || p.client == nil {
		return creationfacts.Source{}, errors.New("invalid Guard capture pairing")
	}
	return p.client.CaptureSource(network)
}

// ProbeCreationCapture keeps the original Prepared/service and selected-client
// seals. A callback cannot replace them with arbitrary retained trace bytes.
func (p *Pair) ProbeCreationCapture(ctx context.Context, tx transactioninput.VerifiedTransaction, q *QualifiedPrepared, cp creationfacts.Checkpoint, network creationfacts.Network) (*rpcexecution.CaptureEvidence, error) {
	if p == nil || !p.lifecycle || p.service == nil || p.client == nil || q == nil || q.origin != p || q.prepared == nil || q.execution == nil {
		return nil, errors.New("invalid Guard capture pairing")
	}
	if _, ok := p.service.EvidenceFor(q.prepared); !ok {
		return nil, errors.New("invalid original Guard preparation")
	}
	return p.client.ProbeCreationCapture(ctx, tx, q.execution, cp, network)
}
