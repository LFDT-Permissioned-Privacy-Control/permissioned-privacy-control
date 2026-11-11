package guardbridge

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/rpcexecution"
)

func TestCurrentPairActualOriginalClientCredentialAndPreparation(t *testing.T) {
	tx := verified(t, []byte{1, 2})
	n := newNode(t, tx)
	n.fullHeader = &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 10, BaseFee: big.NewInt(1)}
	original := pair(t, n, rpcexecution.DefaultLimits())
	expected := networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: n.fullHeader.Hash().Hex(), DeploymentID: "original-source"}
	p, err := original.WithNetwork(expected)
	if err != nil {
		t.Fatal(err)
	}
	q, err := p.AcquireSigned(t.Context(), tx)
	if err != nil {
		t.Fatal("actual bound Guard Prepare", err)
	}
	head := creationfacts.Header{Number: 0, Hash: n.fullHeader.Hash()}
	if err := p.RequireCurrentSource(t.Context(), q, expected, head); err != nil {
		t.Fatal("exact original source denied", err)
	}
	count := len(n.methods)
	other, err := p.WithNetwork(expected)
	if err != nil {
		t.Fatal(err)
	}
	if other.RequireCurrentSource(t.Context(), q, expected, head) == nil {
		t.Fatal("another same-source Pair borrowed preparation")
	}
	client := p.client
	p.client, err = p.client.WithCredential("other")
	if err != nil {
		t.Fatal(err)
	}
	if p.RequireCurrentSource(t.Context(), q, expected, head) == nil {
		t.Fatal("same metadata different credential substituted original source")
	}
	p.client = client
	if len(n.methods) != count {
		t.Fatal("foreign preparation/client reached backend")
	}
	wrong := expected
	wrong.DeploymentID = "other"
	if p.RequireCurrentSource(t.Context(), q, wrong, head) == nil {
		t.Fatal("another expected network substituted")
	}
	q.prepared.Approval.Fingerprint[0] ^= 1
	if p.RequireCurrentSource(t.Context(), q, expected, head) == nil {
		t.Fatal("mutated public approval reached final source gate")
	}
}
