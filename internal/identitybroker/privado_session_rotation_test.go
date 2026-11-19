package identitybroker

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
)

// Fault-injection contract for the private transaction boundary. Actual SQL,
// SDK proofs, HTTP cookies and Core acceptance are covered by identitysql tests.
type evidenceRotationStore struct {
	MultiStore
	binding                                 PrivadoStoreBinding
	family                                  Family
	beforeDecision, beforeGate, afterCommit func()
	failure                                 error
	lostCommit                              bool
	challenges                              int
}

func (m *evidenceRotationStore) Binding() PrivadoStoreBinding { return m.binding }
func (m *evidenceRotationStore) ReadPrivadoFamily(context.Context, Scope, string) (Family, error) {
	return m.family, nil
}
func (m *evidenceRotationStore) BeginPrivadoRenewChallenge(_ context.Context, _ Scope, capture PrivadoHandleCapture, _ Family, _ PrivadoChallengeRecord, gate func() error) (PrivadoBeginCommit, error) {
	m.challenges++
	if !capture.Matches(m.family) || capture.Generation != m.family.Generation || capture.HandleHash != m.family.CurrentHandleHash {
		return PrivadoBeginCommit{}, ErrUnauthorized
	}
	if err := gate(); err != nil {
		return PrivadoBeginCommit{}, err
	}
	return PrivadoBeginCommit{Committed: true, Kind: ChallengeInserted}, nil
}
func (m *evidenceRotationStore) WithProviderFamily(_ context.Context, _ Scope, _ FamilyProvider, _ string, decide func(Family) (FamilyDecision, error), gate func() error) (Commit, error) {
	if m.failure != nil {
		return Commit{}, m.failure
	}
	if m.beforeDecision != nil {
		m.beforeDecision()
	}
	decision, err := decide(m.family)
	if err != nil {
		return Commit{}, err
	}
	if decision.Kind == Rotate {
		if m.beforeGate != nil {
			m.beforeGate()
		}
		if err := gate(); err != nil {
			return Commit{}, err
		}
	}
	if decision.Kind != DenyUnchanged {
		m.family = decision.Family
	}
	if m.afterCommit != nil {
		m.afterCommit()
	}
	if m.lostCommit {
		return Commit{}, ErrUnavailable
	}
	return Commit{Committed: true, Kind: decision.Kind}, nil
}

type evidenceProofStore struct {
	PrivadoProofStore
	binding PrivadoStoreBinding
}

func (m evidenceProofStore) Binding() PrivadoStoreBinding { return m.binding }

func evidenceRotationFixture(t *testing.T, legacy bool) (*Service, *evidenceRotationStore, *time.Time, string, RecipientBinding, int64) {
	t.Helper()
	now := time.Unix(1800000000, 0).UTC()
	snapshot := f.MultiSnapshot(t, func(_ *identity.SourceCatalog, source *brokerpolicy.SourceV2) {
		source.AzureProfiles = []brokerpolicy.AzureBinding{}
	})
	broker, _ := snapshot.AuthBroker()
	binding := ServiceBinding{Environment: "test", DeploymentID: "evidence-rotation", Origin: broker.CommonSettings().WebOrigin}
	namespace, err := binding.Namespace(broker.Issuer().Issuer)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Namespace: namespace, State: ExpectedState{RecoveryEpoch: uuid.NewString()}}
	store := &evidenceRotationStore{binding: PrivadoStoreBinding{Scope: scope, SchemaVersion: 2, Role: "private-app"}}
	service, err := NewMulti(MultiConfig{Snapshot: snapshot, Clock: func() time.Time { return now }, Store: store, PublicProofStore: evidenceProofStore{binding: PrivadoStoreBinding{Scope: scope, SchemaVersion: 2, Role: "public-proof"}}, AccessSigningBinding: AccessSigningBinding{IssuerID: "ops", KeyID: "test", PrivateKey: f.SigningKey()}, RenewalKeyBindings: []SecretBinding{{FromEnv: "OPS_BROKER_REFRESH_TEST", Value: bytes.Repeat([]byte{1}, 32)}}, EncryptionKeyBindings: []SecretBinding{{FromEnv: "OPS_BROKER_ENCRYPTION_TEST", Value: bytes.Repeat([]byte{2}, 32)}}, ServiceBinding: binding, ExpectedState: scope.State})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	digest, _ := service.identity.ProfileDigest(f.PrivadoRoleProfile)
	subject := f.PublicFixtureDID(t, 71)
	actor, err := service.identity.SourceActorID(identity.SourceIdentity{ProfileID: f.PrivadoRoleProfile, Kind: identity.Human, Authority: "privado", Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	recipient := RecipientBinding{1}
	family := Family{Provider: FamilyPrivado, ID: uuid.NewString(), RequestID: uuid.NewString(), Scope: scope, Actor: actor, ProfileID: f.PrivadoRoleProfile, ProfileDigest: digest, Authority: "privado", Subject: subject, Kind: identity.Human, Recipient: recipient, CreatedAt: now, AbsoluteExpiresAt: now.Add(FamilyLifetime), LastRotatedAt: now}
	until := now.Unix() + 100
	evidence := &privadoSessionEvidence{ClaimsAsOf: now.Unix(), VerifiedAt: now.Unix(), NotAfter: until, Predicates: []uint32{1}}
	if legacy {
		evidence = nil
	}
	handle, err := service.privadoFamilyMaterial(&family, now, evidence)
	if err != nil {
		t.Fatal(err)
	}
	store.family = family
	return service, store, &now, handle, recipient, until
}

func TestPrivadoSessionRestoreRotationFailureBoundaries(t *testing.T) {
	for _, stage := range []string{"waiting for lock", "precommit gate", "delivery", "unknown commit", "store unavailable", "legacy family"} {
		t.Run(stage, func(t *testing.T) {
			s, store, now, handle, recipient, until := evidenceRotationFixture(t, stage == "legacy family")
			original := store.family
			advance := func() { *now = time.Unix(until, 0).UTC() }
			switch stage {
			case "waiting for lock":
				store.beforeDecision = advance
			case "precommit gate":
				store.beforeGate = advance
			case "delivery":
				store.afterCommit = advance
			case "unknown commit":
				store.lostCommit = true
			case "store unavailable":
				store.failure = ErrUnavailable
			}
			result, err := s.BootstrapMulti(t.Context(), handle, recipient)
			wantProof := stage == "waiting for lock" || stage == "precommit gate" || stage == "legacy family"
			if wantProof {
				if err != nil || result == nil || store.challenges != 1 || store.family.Generation != original.Generation || store.family.CurrentHandleHash != original.CurrentHandleHash {
					t.Fatal("known nonmutation did not safely require proof", err, store.challenges)
				}
				if _, ok := result.ProofRequired(); !ok {
					t.Fatal("new proof not required")
				}
			} else {
				if err == nil || result != nil || store.challenges != 0 {
					t.Fatal("ambiguous/failed/expired delivery fell back to a proof", err, store.challenges)
				}
				wantGeneration := int64(1)
				if stage == "store unavailable" {
					wantGeneration = 0
				}
				if store.family.Generation != wantGeneration {
					t.Fatal("unexpected committed state", store.family.Generation)
				}
			}
		})
	}
}

func TestPrivadoSessionRestoreReplayAndRecipient(t *testing.T) {
	s, store, now, handle, recipient, until := evidenceRotationFixture(t, false)
	if result, err := s.BootstrapMulti(t.Context(), handle, RecipientBinding{2}); err == nil || result != nil || store.challenges != 0 || store.family.Generation != 0 {
		t.Fatal("wrong recipient changed family", err)
	}
	var stale string
	for i := 0; i < 2; i++ {
		*now = now.Add(time.Second)
		result, err := s.BootstrapMulti(t.Context(), handle, recipient)
		if err != nil {
			t.Fatal(err)
		}
		access, ok := result.Access()
		if !ok || access.Metadata().ExpiresAt.Unix() != until || store.family.Generation != int64(i+1) {
			t.Fatal("restore extended original cutoff or failed to rotate")
		}
		_, successor, err := access.Credentials()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			// Retain the first successor as a stale handle for the replay below.
			stale = successor
		}
		handle = successor
	}
	result, err := s.BootstrapMulti(t.Context(), stale, recipient)
	if !errors.Is(err, ErrRelogin) || result != nil || store.family.RevokedAt == nil || store.challenges != 0 {
		t.Fatal("replayed handle did not revoke without fallback", err)
	}
}

func TestPrivadoSessionRestoreMalformedOrUnauthenticatedEvidenceNeverFallsBack(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "authenticated invalid indices", true: "corrupt ciphertext"}[corrupt], func(t *testing.T) {
			s, store, now, handle, recipient, until := evidenceRotationFixture(t, false)
			if corrupt {
				store.family.Ciphertext = bytes.Clone(store.family.Ciphertext)
				store.family.Ciphertext[len(store.family.Ciphertext)-1] ^= 1
			} else {
				payload, err := s.openPrivadoFamily(store.family)
				if err != nil {
					t.Fatal(err)
				}
				payload.Evidence.Predicates = []uint32{1, 1}
				// Simulate a malformed authenticated server payload, not a fake
				// provider proof. Even original expiry cannot turn it into a miss.
				store.family.Ciphertext, err = s.aes.seal(store.family.EncryptionKeyID, mustJSON(t, payload), privadoFamilyAAD(store.family))
				if err != nil {
					t.Fatal(err)
				}
			}
			*now = time.Unix(until, 0)
			result, err := s.BootstrapMulti(t.Context(), handle, recipient)
			if err == nil || result != nil || store.challenges != 0 || store.family.Generation != 0 {
				t.Fatal("bad evidence became a proof fallback", err)
			}
		})
	}
}
