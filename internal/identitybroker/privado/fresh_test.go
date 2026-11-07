//go:build !prover_disabled

package privado

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	it "github.com/iden3/go-circuits/v2/testing"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-jwz/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
)

// This is one short local functional proof, not a throughput test or a wallet
// interoperability claim. It reads ONLY explicitly pinned public artifacts and
// creates a NEW PUBLIC TEST identity; it never reads a user's identity/seed.
func TestFreshAuthV2ActualProvider(t *testing.T) {
	if os.Getenv("OPS_PRIVADO_FRESH_PROOF") != "1" {
		t.Skip("set OPS_PRIVADO_FRESH_PROOF=1 with cached public artifacts for one fresh real proof")
	}
	dir := os.Getenv("OPS_PRIVADO_AUTHV2_ARTIFACTS")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(home, ".privado-circuits", "authV2")
	}
	artifacts := map[string][]byte{}
	for name, want := range map[string]string{"circuit.wasm": "70affbca1ad1947d76784ca90f6c4a8fd143119685c9917a2a6fefc15b9ed7c1", "circuit_final.zkey": "6acb096a716f5f5b1e5505a7b7261c7eeb7f0a90597c5194fad7b14f91180ac1", "verification_key.json": "79cf543dd8300c0149454ddd200a0a1ac83eed1df4fb49bdceea4b5ebd2cec96"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal("pinned public artifact unavailable")
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("pinned public artifact mismatch", name)
		}
		artifacts[name] = raw
	}
	f := newRPCFixture(t)
	var offset atomic.Int64
	p := f.logicalProvider(t, func() time.Time { return time.Now().Add(time.Duration(offset.Load()) * time.Second) })
	r := fixtureRequest(t, p, "privado")
	request := sdkRequest(t, r)
	// Intentionally public fixed test-only material. This identity exists only
	// in memory inside this test process and is never a production account.
	user := it.NewIdentity(t, strings.Repeat("42", 32))
	typ, err := core.BuildDIDType(core.DIDMethodIden3, core.Polygon, core.Mumbai)
	if err != nil {
		t.Fatal(err)
	}
	id, err := core.NewIDFromIdenState(typ, user.State(t).BigInt())
	if err != nil {
		t.Fatal(err)
	}
	user.ID = *id
	holder, err := core.ParseDIDFromID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	gist := it.GISTTree(t.Context())
	gistProof, _, err := gist.GenerateProof(t.Context(), user.ID.BigInt(), nil)
	if err != nil {
		t.Fatal(err)
	}
	inc, _ := user.ClaimMTPRaw(t, user.AuthClaim)
	nonrev, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)
	now := time.Now().Unix()
	expires := request.ExpiresTime
	// The standard ZKP packer preserves a plain-labelled INNER protocol body;
	// only the protected OUTER media type selects the actual ZKP envelope.
	response := protocol.AuthorizationResponseMessage{ID: uuid.NewString(), Typ: packers.MediaTypePlainMessage, Type: protocol.AuthorizationResponseMessageType, ThreadID: request.ID, From: holder.String(), To: request.From, CreatedTime: &now, ExpiresTime: expires, Body: protocol.AuthorizationMessageResponseBody{Message: request.Body.Message, Scope: []protocol.ZeroKnowledgeProofResponse{}}}
	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwz.NewWithPayload(jwz.ProvingMethodGroth16AuthV2Instance, payload, func(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
		if circuitID != circuits.AuthV2CircuitID {
			return nil, ErrInvalid
		}
		signature, err := user.SignBBJJ(hash)
		if err != nil {
			return nil, err
		}
		input := circuits.AuthV2Inputs{GenesisID: &user.ID, ProfileNonce: big.NewInt(0), AuthClaim: user.AuthClaim, AuthClaimIncMtp: inc, AuthClaimNonRevMtp: nonrev, TreeState: circuits.TreeState{State: user.State(t), ClaimsRoot: user.Clt.Root(), RevocationRoot: user.Ret.Root(), RootOfRoots: user.Rot.Root()}, GISTProof: circuits.GISTProof{Root: gist.Root(), Proof: gistProof}, Signature: signature, Challenge: new(big.Int).SetBytes(hash)}
		return input.InputsMarshal()
	})
	if err != nil {
		t.Fatal(err)
	}
	if token.WithHeader(jwz.HeaderType, packers.MediaTypeZKPMessage) != nil {
		t.Fatal("header")
	}
	started := time.Now()
	compact, err := token.Prove(artifacts["circuit_final.zkey"], artifacts["circuit.wasm"])
	if err != nil {
		t.Fatal("actual fresh proving failed", err)
	}
	proof, err := p.Verify(t.Context(), r, compact)
	if err != nil || proof == nil {
		t.Fatal("actual fresh FullVerify", err)
	}
	if proof.Metadata().HolderDID != holder.String() || len(proof.Facts()) != 0 || proof.RequireCurrent() != nil || proof.Identity().Subject != holder.String() {
		t.Fatal("wrong fresh identity evidence")
	}
	if p.RequireProof(proof) != nil {
		t.Fatal("own provider result pairing failed")
	}
	other := f.logicalProvider(t, nil)
	if other.Metadata() != p.Metadata() || other.RequireProof(proof) == nil {
		t.Fatal("metadata equality substituted another provider instance")
	}
	if f.hits.Load() != 2 || f.chains.Load() != 1 || f.calls.Load() != 1 {
		t.Fatal("proof skipped actual state RPC", f.hits.Load())
	}
	t.Logf("one fresh AuthV2 proof: compactBytes=%d elapsed=%s actualTLSChainChecks=%d actualTLSGISTChecks=%d; pinned embedded verification key", len(compact), time.Since(started).Round(time.Millisecond), f.chains.Load(), f.calls.Load())
	if output := os.Getenv("OPS_PRIVADO_PUBLIC_PROOF_OUT"); output != "" {
		fixture := publicProofFixture{TestOnly: "NEW PUBLIC TEST IDENTITY;32bytes each0x42;not a user credential", Request: r, Compact: compact}
		raw, err := json.Marshal(fixture)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("owned public proof output already exists or unavailable")
		}
		if _, err := file.Write(raw); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	meta := proof.Metadata()
	checkFreshProofRPCFailures(t, r, compact)
	meta.ActorID = "changed"
	if proof.Metadata().ActorID == meta.ActorID {
		t.Fatal("mutable opaque metadata")
	}
	// A new challenge cannot reuse the previous holder proof.
	newRequest := fixtureRequest(t, p, "privado")
	before := f.hits.Load()
	if _, err := p.Verify(t.Context(), newRequest, compact); err == nil || f.hits.Load() != before {
		t.Fatal("old challenge proof replayed")
	}
	// No cache permits a stale replaced GIST to remain accepted, including a
	// malicious future transition timestamp that SDK delay alone could miss.
	f.mode.Store(1)
	if _, err := p.Verify(t.Context(), r, compact); err == nil {
		t.Fatal("actual crypto accepted replaced GIST")
	}
	if f.chains.Load() != 2 || f.calls.Load() != 2 {
		t.Fatal("actual proof state cached across attempts")
	}
	f.mode.Store(0)
	offset.Store(301)
	if proof.RequireCurrent() == nil {
		t.Fatal("opaque evidence lifetime renewed itself")
	}
	if _, err := p.Verify(t.Context(), r, compact); err == nil {
		t.Fatal("old valid crypto accepted after request expiry")
	}
	offset.Store(0)
	// The actual SDK packer reaches this blocking state call with Background.
	// The provider's attempt wrapper must still observe the ORIGINAL caller.
	f.mode.Store(8)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.Verify(ctx, r, compact); done <- err }()
	select {
	case <-f.started:
	case <-time.After(2 * time.Second):
		t.Fatal("actual packer did not reach owned state transport")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled real packer verified")
		}
	case <-time.After(time.Second):
		t.Fatal("real packer detached original request context")
	}
}
