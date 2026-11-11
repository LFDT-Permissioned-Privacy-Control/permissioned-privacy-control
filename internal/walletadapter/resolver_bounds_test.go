package walletadapter

import (
	"context"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/walletops"
	"testing"
	"time"
)

// Trusted-adapter shape/boundary fixture only. Actual EIP191 and restricted SQL
// provenance are qualified by the real wallet/Core/Recorder integration tests.
type boundedOwnershipSource struct {
	rows  []walletops.OwnershipFact
	limit int
}

func (s *boundedOwnershipSource) LoadActive(_ context.Context, _ walletops.Namespace, _ walletops.ExpectedState, _ string, limit int) ([]walletops.OwnershipFact, error) {
	s.limit = limit
	return s.rows, nil
}
func (*boundedOwnershipSource) WithActorTransaction(context.Context, walletops.Namespace, walletops.ExpectedState, string, func(walletops.ActorTx) error) error {
	panic("resolver attempted mutation")
}
func (*boundedOwnershipSource) ResolveActiveActors(context.Context, walletops.Namespace, walletops.ExpectedState, common.Address, int) ([]string, error) {
	panic("resolver attempted directory lookup")
}
func TestResolverMaximumSnapshotAndOverflowAreNotPartialAuthority(t *testing.T) {
	ns := walletops.Namespace{1}
	state := walletops.ExpectedState{Generation: "11111111-1111-1111-1111-111111111111"}
	actor := "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	at := time.Unix(100, 0)
	source := &boundedOwnershipSource{}
	for i := 1; i <= walletops.MaxLinks; i++ {
		var address common.Address
		binary.BigEndian.PutUint64(address[12:], uint64(i))
		source.rows = append(source.rows, walletops.OwnershipFact{Namespace: ns, Actor: actor, Address: address, ProofVersion: 2, VerifiedAt: at})
	}
	resolver, err := New(source, ns, state, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := resolver.Load(t.Context(), actor)
	if err != nil || len(snapshot.Addresses()) != walletops.MaxLinks || source.limit != walletops.MaxLinks+1 || !snapshot.Contains(source.rows[walletops.MaxLinks-1].Address) {
		t.Fatal("maximum valid collection truncated", err)
	}
	last := source.rows[walletops.MaxLinks-1]
	last.Address[0] = 1
	source.rows = append(source.rows, last)
	if _, err := resolver.Load(t.Context(), actor); err == nil {
		t.Fatal("overflow sentinel became partial permission")
	}
	source.rows = source.rows[:walletops.MaxLinks]
	source.rows[0].Actor = "ops:p1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	if _, err := resolver.Load(t.Context(), actor); err == nil {
		t.Fatal("foreign actor fact entered original snapshot")
	}
}
