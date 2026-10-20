package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
)

// MockPrivadoVerifier is a mock implementation of the PrivadoVerifier interface for testing
type MockPrivadoVerifier struct {
	// DefaultDID is the DID to return from VerifyJWZ when not configured per-call
	DefaultDID string
	// DefaultIsHuman determines whether the mock user passes humanity verification
	DefaultIsHuman bool
	// ShouldFail forces verification to fail with an error
	ShouldFail bool
	// FailureError is the error message when ShouldFail is true
	FailureError string
}

// NewMockPrivadoVerifier creates a new mock verifier with default settings
func NewMockPrivadoVerifier() *MockPrivadoVerifier {
	return &MockPrivadoVerifier{
		DefaultDID:     "did:pkh:eip155:1:0x0000000000000000000000000000000000000002",
		DefaultIsHuman: true,
		ShouldFail:     false,
		FailureError:   "mock verification failed",
	}
}

// CreateAuthorizationRequest creates a mock authorization request
func (m *MockPrivadoVerifier) CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error) {
	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailureError)
	}

	reqID := uuid.New().String()
	return &protocol.AuthorizationRequestMessage{
		ID:   reqID,
		Typ:  "application/iden3comm-plain-json",
		Type: "https://iden3-communication.io/authorization/1.0/request",
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
			Scope:       []protocol.ZeroKnowledgeProofRequest{},
		},
		From: verifierID,
	}, nil
}

// CreateHumanityAuthRequest creates a mock authorization request with a ZK
// credential query assembled from hc.
func (m *MockPrivadoVerifier) CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string, hc HumanityRequestConfig) (*protocol.AuthorizationRequestMessage, error) {
	if m.ShouldFail {
		return nil, fmt.Errorf("%s", m.FailureError)
	}

	reqID := uuid.New().String()

	credentialSubject, ok := hc.Query["credentialSubject"]
	if !ok {
		return nil, fmt.Errorf("credential query must contain 'credentialSubject'")
	}

	mtpProofRequest := protocol.ZeroKnowledgeProofRequest{
		ID:        1,
		CircuitID: hc.CircuitID,
		Query: map[string]any{
			"allowedIssuers":    []string{issuerDID},
			"credentialSubject": credentialSubject,
			"context":           hc.SchemaURL,
			"type":              hc.CredentialType,
		},
	}

	return &protocol.AuthorizationRequestMessage{
		ID:   reqID,
		Typ:  "application/iden3comm-plain-json",
		Type: "https://iden3-communication.io/authorization/1.0/request",
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: callbackURL,
			Reason:      reason,
			Scope:       []protocol.ZeroKnowledgeProofRequest{mtpProofRequest},
		},
		From: verifierID,
	}, nil
}

// VerifyJWZ mocks verification of a JWZ token
// For mock tokens in format "mock.{did}" or "mock.jwz.token.{did}", extracts the DID
// For other tokens, returns DefaultDID
func (m *MockPrivadoVerifier) VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error) {
	if m.ShouldFail {
		return "", fmt.Errorf("%s", m.FailureError)
	}

	// Check if humanity proof was required (non-empty scope)
	if len(authRequest.Body.Scope) > 0 && !m.DefaultIsHuman {
		return "", fmt.Errorf("humanity verification failed: user does not have valid ProofOfHumanity credential")
	}

	return m.DefaultDID, nil
}

// SetDID sets the default DID to return
func (m *MockPrivadoVerifier) SetDID(did string) {
	m.DefaultDID = did
}

// SetIsHuman sets whether the mock user passes humanity verification
func (m *MockPrivadoVerifier) SetIsHuman(isHuman bool) {
	m.DefaultIsHuman = isHuman
}

// SetShouldFail configures the mock to fail with the given error
func (m *MockPrivadoVerifier) SetShouldFail(shouldFail bool, errorMsg string) {
	m.ShouldFail = shouldFail
	m.FailureError = errorMsg
}
