package privado

import (
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
)

func TestRealSigV2PrimitiveDoesNotMakeOldEvidenceFresh(t *testing.T) {
	// Numeric public proof only, copied from pinned go-iden3-auth/v2@v2.8.1
	// TestVerifyMessageWithSigProof_NonMerkalized. Timestamp1694787248 is old.
	// A primitive verification positive is NOT a provider/login positive.
	raw, err := os.ReadFile("testdata/sig-v2-primitive.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof types.ZKProof
	if json.Unmarshal(raw, &proof) != nil {
		t.Fatal("primitive fixture")
	}
	key, err := loaders.NewEmbeddedKeyLoader().Load(circuits.AtomicQuerySigV2CircuitID)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyGroth16(proof, key); err != nil {
		t.Fatal("real SigV2 Groth16 primitive", err)
	}
	var signals circuits.AtomicQuerySigV2PubSignals
	pub, _ := json.Marshal(proof.PubSignals)
	if signals.PubSignalsUnmarshal(pub) != nil {
		t.Fatal("typed SDK signals")
	}
	if roleTimeCurrent(signals.Timestamp, signals.Timestamp, time.Now().Unix()) {
		t.Fatal("production age gate accepts old real proof")
	}
	changed := proof
	changed.PubSignals = slices.Clone(proof.PubSignals)
	n, _ := new(big.Int).SetString(changed.PubSignals[1], 10)
	changed.PubSignals[1] = n.Add(n, big.NewInt(1)).String()
	if verifier.VerifyGroth16(changed, key) == nil {
		t.Fatal("real verifier accepted altered public inputs")
	}
}
