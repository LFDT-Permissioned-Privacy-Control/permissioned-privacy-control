//go:build prover_disabled

package privado

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/iden3/go-rapidsnark/prover"
)

// The positive verifies the SAME newly generated public test proof in another
// process/build. Disabling the unused native C prover must not disable, replace
// or stub the actual production Groth16 verifier.
func TestImportedFreshAuthV2WithDisabledProver(t *testing.T) {
	input := os.Getenv("OPS_PRIVADO_PUBLIC_PROOF_IN")
	if input == "" {
		t.Skip("requires labelled NEW public test-only request/proof from the short native fresh qualification")
	}
	raw, err := os.ReadFile(input)
	if err != nil || len(raw) > 128<<10 {
		t.Fatal("owned public proof fixture unavailable/oversized")
	}
	var fixture publicProofFixture
	if json.Unmarshal(raw, &fixture) != nil || fixture.TestOnly != "NEW PUBLIC TEST IDENTITY;32bytes each0x42;not a user credential" {
		t.Fatal("not the owned public test fixture")
	}
	if _, err := prover.Groth16Prover(nil, nil); err == nil || !strings.Contains(err.Error(), "prover disabled") {
		t.Fatal("disabled-prover build not active")
	}
	f := newRPCFixture(t)
	p := f.logicalProvider(t, nil)
	proof, err := p.Verify(t.Context(), fixture.Request, fixture.Compact)
	if err != nil || proof == nil || proof.RequireCurrent() != nil || len(proof.Facts()) != 0 {
		t.Fatal("actual tagged fresh verification", err)
	}
	if f.chains.Load() != 1 || f.calls.Load() != 1 {
		t.Fatal("tagged verification skipped actual TLS state calls")
	}
	t.Log("actual fresh AuthV2 proof verified through real Go Groth16 and owned TLS with native C prover disabled; no success stub")
	checkFreshProofRPCFailures(t, fixture.Request, fixture.Compact)
}
