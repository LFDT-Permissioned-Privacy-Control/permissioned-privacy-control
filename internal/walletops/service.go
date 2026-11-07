package walletops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/walletproof"
)

type Config struct {
	Snapshot *policybundle.CatalogSnapshot
	Clock    identity.Clock
	Binding  ServiceBinding
	State    ExpectedState
	Store    Store
	ENS      ENSResolver
	Audit    AuditSink
}
type Service struct {
	factory   *runtimepolicy.Factory
	clock     identity.Clock
	binding   ServiceBinding
	namespace Namespace
	state     ExpectedState
	store     Store
	ens       ENSResolver
	audit     AuditSink
}

func New(c Config) (*Service, error) {
	if c.Snapshot == nil || c.Clock == nil || c.Store == nil || !c.State.Valid() {
		return nil, ErrInvalid
	}
	namespace, err := c.Binding.Namespace()
	if err != nil {
		return nil, err
	}
	metadata := c.Snapshot.Metadata()
	if metadata.Environment != c.Binding.Environment || metadata.ChainID != c.Binding.ChainID {
		return nil, ErrInvalid
	}
	factory, err := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if err != nil {
		return nil, ErrInvalid
	}
	return &Service{factory, c.Clock, c.Binding, namespace, c.State, c.Store, c.ENS, c.Audit}, nil
}

type Response struct {
	body []byte
	gate func() error
}

func (r *Response) WriteTo(w io.Writer) (int64, error) {
	if err := r.gate(); err != nil {
		return 0, err
	}
	n, err := w.Write(r.body)
	return int64(n), err
}
func (s *Service) view(token string) (*runtimepolicy.View, error) {
	v, err := s.factory.Build(token)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return v, nil
}
func live(v *runtimepolicy.View) error {
	if v.RequireLive() != nil {
		return ErrUnauthorized
	}
	return nil
}
func result(value any, v *runtimepolicy.View) (*Response, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > MaxResponseBytes {
		return nil, ErrUnavailable
	}
	return &Response{append(raw, '\n'), func() error { return live(v) }}, nil
}
func (s *Service) emit(v *runtimepolicy.View, address, action string, at time.Time) {
	select {
	case s.audit <- AuditEvent{v.ActorID(), address, action, at}:
	default:
	}
}
func (s *Service) Issue(ctx context.Context, token string, req ChallengeRequest) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	address, err := ParseAddress(req.Address)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC().Truncate(time.Second)
	c := Challenge{Namespace: s.namespace, Generation: s.state.Generation, Actor: v.ActorID(), Address: address, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	c.Message, err = walletproof.Message(walletproof.MessageFields{Origin: s.binding.ServiceOrigin, Namespace: c.Namespace.String(), Actor: c.Actor, Address: AddressString(address), Nonce: hex.EncodeToString(c.Nonce[:]), IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt})
	if err != nil {
		return nil, ErrInvalid
	}
	err = s.store.WithActorTransaction(ctx, s.namespace, s.state, v.ActorID(), func(tx ActorTx) error {
		if err := live(v); err != nil {
			return err
		}
		link, found, err := tx.GetLink(address)
		if err != nil {
			return err
		}
		if found && link.Revoked {
			return ErrConflict
		}
		if !found {
			n, err := tx.CountLinkRows()
			if err != nil {
				return err
			}
			if n >= MaxLinks {
				return ErrConflict
			}
		}
		if err := tx.DeleteExpiredChallenges(now, MaxChallenges); err != nil {
			return err
		}
		n, err := tx.CountChallenges()
		if err != nil {
			return err
		}
		if n >= MaxChallenges {
			return ErrConflict
		}
		if err := tx.InsertChallenge(c); err != nil {
			return err
		}
		return live(v)
	})
	if err != nil {
		return nil, err
	}
	return result(ChallengeResult{hex.EncodeToString(c.Nonce[:]), c.Message, c.ExpiresAt.Format(time.RFC3339)}, v)
}
func (s *Service) Verify(ctx context.Context, token string, req VerifyRequest) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	address, err := ParseAddress(req.Address)
	if err != nil {
		return nil, err
	}
	nonce, err := ParseNonce(req.Nonce)
	if err != nil {
		return nil, err
	}
	signature, err := walletproof.Signature(req.Signature)
	if err != nil {
		return nil, ErrInvalid
	}
	var now time.Time
	inserted := false
	err = s.store.WithActorTransaction(ctx, s.namespace, s.state, v.ActorID(), func(tx ActorTx) error {
		if err := live(v); err != nil {
			return err
		}
		// The actor lock may have waited on another replica. Challenge time
		// starts here, after lock acquisition, rather than at HTTP arrival.
		now = s.clock().UTC().Truncate(time.Second)
		c, found, err := tx.TakeChallenge(nonce, address, now)
		if err != nil {
			return err
		}
		if !found {
			return ErrConflict
		}
		if c.Namespace != s.namespace || c.Generation != s.state.Generation || c.Actor != v.ActorID() || c.Address != address || c.Nonce != nonce || c.Validate(s.binding.ServiceOrigin) != nil || c.IssuedAt.After(now) || !now.Before(c.ExpiresAt) {
			return ErrUnavailable
		}
		valid := func() error {
			at := s.clock()
			if at.Before(c.IssuedAt) || !at.Before(c.ExpiresAt) {
				return ErrConflict
			}
			return live(v)
		}
		recovered, err := walletproof.RecoverV2(c.Message, signature)
		if err != nil || recovered != address {
			return ErrInvalid
		}
		link, exists, err := tx.GetLink(address)
		if err != nil {
			return err
		}
		if exists {
			if link.Revoked {
				return ErrConflict
			}
			return valid()
		}
		n, err := tx.CountLinkRows()
		if err != nil {
			return err
		}
		if n >= MaxLinks {
			return ErrConflict
		}
		link = Link{Namespace: s.namespace, Actor: v.ActorID(), Address: address, ProofKind: "eip191_v2", Message: c.Message, Signature: signature, MessageHash: walletproof.HashMessage(c.Message), AcceptedAt: now}
		inserted, err = tx.InsertOwnership(link)
		if err != nil {
			return err
		}
		return valid()
	})
	if err != nil {
		return nil, err
	}
	if inserted {
		s.emit(v, AddressString(address), "link", now)
	}
	return result(LinkResult{AddressString(address), "linked"}, v)
}
func (s *Service) Own(ctx context.Context, token string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	facts, err := s.store.LoadActive(ctx, s.namespace, s.state, v.ActorID(), MaxLinks+1)
	if err != nil {
		return nil, err
	}
	if len(facts) > MaxLinks {
		return nil, ErrUnavailable
	}
	out := make([]OwnAddress, 0, len(facts))
	seen := map[string]bool{}
	for _, f := range facts {
		if !f.Valid(s.namespace, v.ActorID()) {
			return nil, ErrUnavailable
		}
		address := AddressString(f.Address)
		if seen[address] {
			return nil, ErrUnavailable
		}
		seen[address] = true
		out = append(out, OwnAddress{address, f.VerifiedAt.UTC().Format(time.RFC3339), f.ProofVersion})
	}
	return result(out, v)
}
func (s *Service) Unlink(ctx context.Context, token, rawAddress string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	address, err := ParseAddress(rawAddress)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC().Truncate(time.Second)
	changed := false
	err = s.store.WithActorTransaction(ctx, s.namespace, s.state, v.ActorID(), func(tx ActorTx) error {
		if err := live(v); err != nil {
			return err
		}
		found, mutated, err := tx.Revoke(address, now)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		changed = mutated
		return live(v)
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.emit(v, AddressString(address), "unlink", now)
	}
	return result(LinkResult{AddressString(address), "revoked"}, v)
}
func (s *Service) RefreshENS(ctx context.Context, token, rawAddress string) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	address, err := ParseAddress(rawAddress)
	if err != nil {
		return nil, err
	}
	facts, err := s.store.LoadActive(ctx, s.namespace, s.state, v.ActorID(), MaxLinks+1)
	if err != nil {
		return nil, err
	}
	if len(facts) > MaxLinks {
		return nil, ErrUnavailable
	}
	found := false
	for _, f := range facts {
		if !f.Valid(s.namespace, v.ActorID()) {
			return nil, ErrUnavailable
		}
		found = found || f.Address == address
	}
	if !found {
		return nil, ErrNotFound
	}
	if s.ens == nil {
		return nil, ErrUnavailable
	}
	metadata, err := s.ens.Lookup(ctx, address)
	if err != nil || len(metadata.Name) > 255 || !utf8.ValidString(metadata.Name) || (metadata.Name != "" && (!text(metadata.Name, 255) || metadata.ForwardAddress != address)) {
		return nil, ErrUnavailable
	}
	return result(ENSResult{AddressString(address), metadata.Name}, v)
}
