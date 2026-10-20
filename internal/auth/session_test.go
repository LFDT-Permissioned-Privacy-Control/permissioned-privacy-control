package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/iden3/iden3comm/v2/protocol"
)

func TestNewSessionStore(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Minute)
	defer store.Stop()

	if store == nil {
		t.Fatal("NewSessionStore() returned nil")
	}

	if store.ttl != 10*time.Minute {
		t.Errorf("NewSessionStore() ttl = %v, want %v", store.ttl, 10*time.Minute)
	}
}

func TestSessionStore_CreateSession(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	authRequest := &protocol.AuthorizationRequestMessage{
		ID: "test-auth-request",
	}

	tests := []struct {
		name string
	}{
		{"should create session with unique ID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionID1 := store.CreateSession(authRequest)

			// Verify session ID is not empty
			if sessionID1 == "" {
				t.Error("CreateSession() returned empty session ID")
			}

			// Verify session can be retrieved
			session := store.GetSession(sessionID1)
			if session == nil {
				t.Error("GetSession() returned nil for created session")
			}

			if session.AuthRequest != authRequest {
				t.Error("GetSession() returned wrong auth request")
			}

			// Verify unique IDs
			sessionID2 := store.CreateSession(authRequest)
			if sessionID1 == sessionID2 {
				t.Error("CreateSession() returned duplicate session IDs")
			}
		})
	}
}

func TestSessionStore_GetSession(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	authRequest := &protocol.AuthorizationRequestMessage{
		ID: "test-auth-request",
	}

	t.Run("should return session for valid ID", func(t *testing.T) {
		sessionID := store.CreateSession(authRequest)

		session := store.GetSession(sessionID)
		if session == nil {
			t.Fatal("GetSession() returned nil")
		}

		if session.ID != sessionID {
			t.Errorf("session.ID = %q, want %q", session.ID, sessionID)
		}

		if session.AuthRequest.ID != authRequest.ID {
			t.Error("session.AuthRequest doesn't match")
		}
	})

	t.Run("should return nil for non-existent session", func(t *testing.T) {
		session := store.GetSession("nonexistent-id")
		if session != nil {
			t.Error("GetSession() should return nil for non-existent session")
		}
	})

	t.Run("should return nil for expired session", func(t *testing.T) {
		// Create store with very short TTL
		shortStore := NewSessionStore(1*time.Millisecond, 1*time.Hour)
		defer shortStore.Stop()

		sessionID := shortStore.CreateSession(authRequest)

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		session := shortStore.GetSession(sessionID)
		if session != nil {
			t.Error("GetSession() should return nil for expired session")
		}
	})
}

func TestSessionStore_DeleteSession(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	authRequest := &protocol.AuthorizationRequestMessage{
		ID: "test-auth-request",
	}

	t.Run("should delete existing session", func(t *testing.T) {
		sessionID := store.CreateSession(authRequest)

		// Verify session exists
		if store.GetSession(sessionID) == nil {
			t.Fatal("Session should exist before deletion")
		}

		store.DeleteSession(sessionID)

		// Verify session is gone
		if store.GetSession(sessionID) != nil {
			t.Error("Session should be deleted")
		}
	})

	t.Run("should not panic on non-existent session", func(t *testing.T) {
		// Should not panic
		store.DeleteSession("nonexistent-id")
	})
}

func TestSessionStore_UpdateSession(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	authRequest1 := &protocol.AuthorizationRequestMessage{
		ID: "auth-request-1",
	}
	authRequest2 := &protocol.AuthorizationRequestMessage{
		ID: "auth-request-2",
	}

	t.Run("should update existing session", func(t *testing.T) {
		sessionID := store.CreateSession(authRequest1)

		err := store.UpdateSession(sessionID, authRequest2)
		if err != nil {
			t.Errorf("UpdateSession() error = %v", err)
		}

		session := store.GetSession(sessionID)
		if session == nil {
			t.Fatal("GetSession() returned nil")
		}

		if session.AuthRequest.ID != authRequest2.ID {
			t.Errorf("session.AuthRequest.ID = %q, want %q", session.AuthRequest.ID, authRequest2.ID)
		}
	})

	t.Run("should return error for non-existent session", func(t *testing.T) {
		err := store.UpdateSession("nonexistent-id", authRequest2)
		if err == nil {
			t.Error("UpdateSession() should return error for non-existent session")
		}
	})
}

func TestSessionStore_Cleanup(t *testing.T) {
	// Create store with very short TTL and cleanup interval
	store := NewSessionStore(50*time.Millisecond, 100*time.Millisecond)
	defer store.Stop()

	authRequest := &protocol.AuthorizationRequestMessage{
		ID: "test-auth-request",
	}

	// Create multiple sessions
	sessionID1 := store.CreateSession(authRequest)
	sessionID2 := store.CreateSession(authRequest)

	// Verify sessions exist
	if store.GetSession(sessionID1) == nil || store.GetSession(sessionID2) == nil {
		t.Fatal("Sessions should exist initially")
	}

	// Wait for expiration and cleanup
	time.Sleep(200 * time.Millisecond)

	// Verify sessions are cleaned up
	if store.GetSession(sessionID1) != nil {
		t.Error("Session 1 should be cleaned up")
	}
	if store.GetSession(sessionID2) != nil {
		t.Error("Session 2 should be cleaned up")
	}
}

func TestSessionStore_Stop(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 100*time.Millisecond)

	authRequest := &protocol.AuthorizationRequestMessage{
		ID: "test-auth-request",
	}

	store.CreateSession(authRequest)

	// Stop should not panic
	store.Stop()

	// Operations should still work after stop (just no cleanup)
	sessionID := store.CreateSession(authRequest)
	if store.GetSession(sessionID) == nil {
		t.Error("Store should still work after Stop()")
	}
}

func TestSessionStore_Concurrency(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	authRequest := &protocol.AuthorizationRequestMessage{
		ID: "test-auth-request",
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // create, get, delete operations

	sessionIDs := make(chan string, numGoroutines)

	// Concurrent creates
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			sessionID := store.CreateSession(authRequest)
			sessionIDs <- sessionID
		}()
	}

	// Concurrent gets
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			select {
			case sessionID := <-sessionIDs:
				store.GetSession(sessionID)
				sessionIDs <- sessionID
			case <-time.After(100 * time.Millisecond):
			}
		}()
	}

	// Concurrent deletes
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			select {
			case sessionID := <-sessionIDs:
				store.DeleteSession(sessionID)
			case <-time.After(100 * time.Millisecond):
			}
		}()
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - no data race
	case <-time.After(5 * time.Second):
		t.Error("Test timed out - possible deadlock")
	}
}

func TestSession_Fields(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	authRequest := &protocol.AuthorizationRequestMessage{
		ID: "test-auth-request",
	}

	now := time.Now()
	sessionID := store.CreateSession(authRequest)
	session := store.GetSession(sessionID)

	if session == nil {
		t.Fatal("GetSession() returned nil")
	}

	t.Run("should have correct ID", func(t *testing.T) {
		if session.ID != sessionID {
			t.Errorf("session.ID = %q, want %q", session.ID, sessionID)
		}
	})

	t.Run("should have auth request", func(t *testing.T) {
		if session.AuthRequest != authRequest {
			t.Error("session.AuthRequest mismatch")
		}
	})

	t.Run("should have CreatedAt near now", func(t *testing.T) {
		if session.CreatedAt.Before(now.Add(-1*time.Second)) || session.CreatedAt.After(now.Add(1*time.Second)) {
			t.Errorf("session.CreatedAt = %v, want near %v", session.CreatedAt, now)
		}
	})

	t.Run("should have ExpiresAt in the future", func(t *testing.T) {
		expectedExpiry := now.Add(10 * time.Minute)
		if session.ExpiresAt.Before(expectedExpiry.Add(-1*time.Second)) || session.ExpiresAt.After(expectedExpiry.Add(1*time.Second)) {
			t.Errorf("session.ExpiresAt = %v, want near %v", session.ExpiresAt, expectedExpiry)
		}
	})
}
