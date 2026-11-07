package privado

import (
	"bytes"
	"context"
	"encoding/json"

	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/piprate/json-gold/ld"
	"privacy-proxy/internal/identity"
)

func (p *Provider) Verify(ctx context.Context, request Request, compact string) (*VerifiedProof, error) {
	// Admission precedes parsing, allocation of SDK public signals/bigints and
	// verifier construction. No queue and no detached proof-verification worker.
	if p == nil || p.closed.Load() {
		return nil, ErrProvider
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		return nil, ErrBusy
	}
	ctx, cancel := operation(ctx)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ErrProvider
	}
	expected, err := p.CreateRequest(request.Context)
	if err != nil {
		return nil, ErrEvidence
	}
	if request.Provider != expected.Provider || request.ProfileDigest != expected.ProfileDigest || request.Context != expected.Context || len(request.AuthorizationJSON) > MaxRequestBytes || !bytes.Equal(request.AuthorizationJSON, expected.AuthorizationJSON) {
		return nil, ErrEvidence
	}
	var sdkRequest protocol.AuthorizationRequestMessage
	if json.Unmarshal(expected.AuthorizationJSON, &sdkRequest) != nil {
		return nil, ErrInvalid
	}
	profile := p.profiles[request.Context.ProfileID]
	now, err := p.now()
	if err != nil {
		return nil, err
	}
	parsed, err := parseCompact(compact, sdkRequest, profile, now)
	if err != nil {
		return nil, err
	}
	if parsed.claimsAsOf+300 <= now {
		return nil, ErrEvidence
	}
	started := now
	a := newAttempt(ctx, p, parsed)
	defer a.close()
	verifier, err := auth.NewVerifier(loaders.NewEmbeddedKeyLoader(), a.resolvers(), auth.WithDocumentLoader(documentLoader{p}), auth.WithStateVerificationOpts(pubsignals.WithAcceptedStateTransitionDelay(0)))
	if err != nil {
		return nil, ErrProvider
	}
	verifier.SetPackageManager(*iden3comm.NewPackageManager())
	if verifier.SetupAuthV2ZKPPacker(auth.WithVerifyStateOpts(pubsignals.WithAcceptedStateTransitionDelay(0))) != nil {
		return nil, ErrProvider
	}
	response, err := verifier.FullVerify(ctx, compact, sdkRequest, pubsignals.WithAcceptedStateTransitionDelay(0), pubsignals.WithAcceptedProofGenerationDelay(MaxAge))
	if ctx.Err() != nil || a.unavailable.Load() {
		return nil, ErrProvider
	}
	if err != nil || response == nil {
		return nil, ErrEvidence
	}
	if ctx.Err() != nil {
		return nil, ErrProvider
	}
	// The exact original compact bytes went through FullVerify. This equality is
	// a parser/SDK agreement check, not a substitute for any proof algorithm.
	if !sameResponse(*response, parsed.response) {
		return nil, ErrEvidence
	}
	now, err = p.now()
	if err != nil {
		return nil, err
	}
	notAfter := min(request.Context.ExpiresAt.Unix(), parsed.claimsAsOf+300)
	if now < started || now < request.Context.CreatedAt.Unix()-30 || now >= notAfter {
		return nil, ErrEvidence
	}
	// Recheck mutable clock after crypto/state I/O, including future-role times.
	if _, err := parseCompact(compact, sdkRequest, profile, now); err != nil {
		return nil, err
	}
	actor, err := p.catalog.SourceActorID(identity.SourceIdentity{ProfileID: profile.source.ID, Kind: identity.Human, Authority: "privado", Subject: response.From})
	if err != nil || request.Context.Mode == Renew && actor != request.Context.ExpectedActorID {
		return nil, ErrEvidence
	}
	facts := make([]identity.Fact, 0, len(profile.source.Predicates))
	for _, predicate := range profile.source.Predicates {
		facts = append(facts, identity.Fact{Kind: "privado.predicate", Value: predicate.ID})
	}
	result := &VerifiedProof{provider: p, metadata: ProofMetadata{Provider: p.metadata, ProfileID: profile.source.ID, ProfileDigest: profile.digest, HolderDID: response.From, ActorID: actor, ClaimsAsOf: parsed.claimsAsOf, SourceVerifiedAt: now, NotAfter: notAfter}, facts: facts, valid: true}
	if err := result.RequireCurrent(); err != nil {
		return nil, err
	}
	return result, nil
}
func sameResponse(a, b protocol.AuthorizationResponseMessage) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

type documentLoader struct{ provider *Provider }

func (l documentLoader) LoadDocument(uri string) (*ld.RemoteDocument, error) {
	raw, ok := l.provider.documents[uri]
	if !ok || l.provider.closed.Load() {
		return nil, ErrProvider
	}
	var document any
	if json.Unmarshal(raw, &document) != nil {
		return nil, ErrProvider
	}
	// Fresh decoded value: json-gold cannot mutate another concurrent request's
	// pinned context. No filesystem/HTTP/IPFS/global loader fallback exists.
	return &ld.RemoteDocument{DocumentURL: uri, Document: document}, nil
}
