// Package walletadapter converts trusted operational ownership into bounded
// native request facts and freezes visibleTo identities at admission.
package walletadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/walletops"
)

type Resolver struct {
	store     walletops.Store
	namespace walletops.Namespace
	state     walletops.ExpectedState
	clock     identity.Clock
}

func New(store walletops.Store, namespace walletops.Namespace, state walletops.ExpectedState, clock identity.Clock) (*Resolver, error) {
	if store == nil || !state.Valid() || clock == nil {
		return nil, walletops.ErrInvalid
	}
	return &Resolver{store, namespace, state, clock}, nil
}
func (r *Resolver) Load(ctx context.Context, actor string) (nativeadmission.WalletSnapshot, error) {
	if !identity.ValidActorID(actor) {
		return nativeadmission.WalletSnapshot{}, walletops.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	facts, err := r.store.LoadActive(ctx, r.namespace, r.state, actor, walletops.MaxLinks+1)
	if err != nil {
		return nativeadmission.WalletSnapshot{}, err
	}
	evidenceAt := r.clock()
	if len(facts) > walletops.MaxLinks {
		return nativeadmission.WalletSnapshot{}, walletops.ErrUnavailable
	}
	addresses := make([]common.Address, 0, len(facts))
	for _, f := range facts {
		if !f.Valid(r.namespace, actor) {
			return nativeadmission.WalletSnapshot{}, walletops.ErrUnavailable
		}
		addresses = append(addresses, f.Address)
	}
	version, err := snapshotVersion(r.namespace, r.state, actor, addresses)
	if err != nil {
		return nativeadmission.WalletSnapshot{}, err
	}
	return nativeadmission.NewWalletSnapshot(actor, version, evidenceAt, addresses)
}

func snapshotVersion(namespace walletops.Namespace, state walletops.ExpectedState, actor string, addresses []common.Address) (string, error) {
	if !state.Valid() || !identity.ValidActorID(actor) || len(addresses) > walletops.MaxLinks {
		return "", walletops.ErrInvalid
	}
	ordered := slices.Clone(addresses)
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i][:], ordered[j][:]) < 0 })
	h := sha256.New()
	part := func(raw []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
		h.Write(size[:])
		h.Write(raw)
	}
	for _, raw := range [][]byte{[]byte("ops-wallet-snapshot/v1"), namespace[:], []byte(state.Generation), state.Coverage[:], []byte(actor)} {
		part(raw)
	}
	for i, address := range ordered {
		if i > 0 && address == ordered[i-1] {
			return "", walletops.ErrUnavailable
		}
		part(address[:])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

const MaxRecipients = 32

type Audience struct{ actors []string }

func (a Audience) Actors() []string { return slices.Clone(a.actors) }

// ResolveRecipients is internal only: callers must first authorize the send and
// source read profile. Returned audiences contain ActorIDs, never live addresses.
func (r *Resolver) ResolveRecipients(ctx context.Context, entries []string) (Audience, error) {
	if len(entries) > MaxRecipients {
		return Audience{}, walletops.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := []string{}
	seen := map[string]bool{}
	for _, entry := range entries {
		actor := entry
		if !identity.ValidActorID(actor) {
			address, err := walletops.ParseAddress(entry)
			if err != nil {
				return Audience{}, walletops.ErrInvalid
			}
			actors, err := r.store.ResolveActiveActors(ctx, r.namespace, r.state, address, 2)
			if err != nil {
				return Audience{}, err
			}
			if len(actors) != 1 || !identity.ValidActorID(actors[0]) {
				return Audience{}, walletops.ErrConflict
			}
			actor = actors[0]
		}
		if !seen[actor] {
			seen[actor] = true
			out = append(out, actor)
		}
	}
	return Audience{out}, nil
}
