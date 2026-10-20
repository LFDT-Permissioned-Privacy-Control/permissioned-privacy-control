package auth

import (
	"testing"
	"time"

	"github.com/iden3/iden3comm/v2/protocol"
)

// ---------------------------------------------------------------------------
// IsValidAddress
// ---------------------------------------------------------------------------

func TestIsValidAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"0x1234567890123456789012345678901234567890", true},
		{"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"0x0000000000000000000000000000000000000000", true},
		{"not-an-address", false},
		{"", false},
		{"0x123", false},
		{"1234567890123456789012345678901234567890", true}, // go-ethereum accepts no-0x prefix
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := IsValidAddress(tc.input)
			if got != tc.expected {
				t.Errorf("IsValidAddress(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SessionStore.CompleteSession, Count, ListSessions
// ---------------------------------------------------------------------------

func TestSessionStore_CompleteSession(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	authReq := &protocol.AuthorizationRequestMessage{ID: "req-complete"}
	sessionID := store.CreateSession(authReq)

	if err := store.CompleteSession(sessionID, "access-token", "refresh-token"); err != nil {
		t.Fatalf("CompleteSession: %v", err)
	}

	session := store.GetSession(sessionID)
	if session == nil {
		t.Fatal("GetSession returned nil")
	}
	if !session.Completed {
		t.Error("session should be completed")
	}
	if session.AccessToken != "access-token" {
		t.Errorf("AccessToken = %q, want %q", session.AccessToken, "access-token")
	}
}

func TestSessionStore_CompleteSession_NotFound(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	err := store.CompleteSession("nonexistent-session", "a", "r")
	if err == nil {
		t.Error("expected error for nonexistent session")
	}
}

func TestSessionStore_Count(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	if store.Count() != 0 {
		t.Errorf("initial count should be 0, got %d", store.Count())
	}

	authReq := &protocol.AuthorizationRequestMessage{ID: "req-count"}
	store.CreateSession(authReq)

	if store.Count() != 1 {
		t.Errorf("count should be 1 after creating a session, got %d", store.Count())
	}
}

func TestSessionStore_ListSessions(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	// Empty at start
	if sessions := store.ListSessions(); len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}

	// Add a session
	authReq := &protocol.AuthorizationRequestMessage{ID: "req-list"}
	sessionID := store.CreateSession(authReq)

	sessions := store.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].ID != sessionID {
		t.Errorf("session ID mismatch: got %q, want %q", sessions[0].ID, sessionID)
	}
	if sessions[0].Completed {
		t.Error("session should not be completed yet")
	}

	// Complete it and verify ListSessions shows it as completed
	if err := store.CompleteSession(sessionID, "tok", "refresh"); err != nil {
		t.Fatalf("CompleteSession: %v", err)
	}

	sessions = store.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after complete, got %d", len(sessions))
	}
	if !sessions[0].Completed {
		t.Error("session should be marked completed in ListSessions")
	}
}
