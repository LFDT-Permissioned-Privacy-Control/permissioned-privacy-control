package walletsql

import (
	"context"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/identity"
	w "privacy-proxy/internal/walletops"
)

// A single MVCC statement anchors even the empty result to the selected ready
// store state. The global sentinel bounds materialization across ALL actors.
// SQL collation order is not the canonical protocol order; the consumer sorts
// only after establishing that the complete set contains at most MaxLinks.
const loadActiveManySQL = `SELECT s.ready AND s.generation=$2::uuid AND s.revocation_coverage_digest=$3
 AND NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_class c
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='ops_wallet_v2' AND c.relname IN('store_state','wallet_links')
   AND(c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity)
 ) AS ready,l.actor_id,l.address,l.accepted_at
FROM ops_wallet_v2.store_state s
LEFT JOIN LATERAL(
 SELECT actor_id,address,accepted_at FROM ops_wallet_v2.wallet_links
 WHERE namespace=s.namespace AND actor_id=ANY($4::text[])
 AND NOT revoked AND proof_kind='eip191_v2'
 ORDER BY actor_id,address LIMIT 4097
) l ON true
WHERE s.namespace=$1
`

var _ w.MultiReader = (*Store)(nil)

// LoadActiveMany reads current link-time associations using the existing
// read-only role. It does not qualify historical ownership or data provenance.
func (s *Store) LoadActiveMany(ctx context.Context, ns w.Namespace, state w.ExpectedState, actors []string) ([]w.OwnershipFact, error) {
	if s == nil || s.mode != "reader" || !state.Valid() || len(actors) < 1 || len(actors) > w.MaxSnapshotActors {
		return nil, w.ErrInvalid
	}
	actors = slices.Clone(actors)
	for i, actor := range actors {
		if !identity.ValidActorID(actor) || i > 0 && actors[i-1] >= actor {
			return nil, w.ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx, loadActiveManySQL, ns[:], state.Generation, state.Coverage[:], actors)
	if err != nil {
		return nil, w.ErrUnavailable
	}
	defer rows.Close()
	out := []w.OwnershipFact{}
	stateSeen := false
	for rows.Next() {
		var ready bool
		var actor *string
		var address []byte
		var at *time.Time
		if rows.Scan(&ready, &actor, &address, &at) != nil || !ready {
			return nil, w.ErrUnavailable
		}
		stateSeen = true
		if actor == nil && address == nil && at == nil {
			continue
		}
		if actor == nil || len(address) != 20 || at == nil || !identity.ValidActorID(*actor) {
			return nil, w.ErrUnavailable
		}
		if _, selected := slices.BinarySearch(actors, *actor); !selected {
			return nil, w.ErrUnavailable
		}
		fact := w.OwnershipFact{Namespace: ns, Actor: *actor, Address: common.BytesToAddress(address), ProofVersion: 2, VerifiedAt: at.UTC()}
		if !fact.Valid(ns, *actor) || len(out) >= w.MaxLinks+1 {
			return nil, w.ErrUnavailable
		}
		out = append(out, fact)
	}
	if rows.Err() != nil || !stateSeen {
		return nil, w.ErrUnavailable
	}
	return out, nil
}
