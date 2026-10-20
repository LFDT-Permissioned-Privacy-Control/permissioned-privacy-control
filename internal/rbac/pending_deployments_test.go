package rbac

import (
	"sync"
	"testing"
	"time"
)

func TestPendingDeploymentTracker_TrackAndGet(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	deployment := &PendingDeployment{
		TxHash:            "0x123",
		OrgID:             "org1",
		IsPlainCreate:     true,
		PreRegisteredAddr: "0xabc",
		SubmittedAt:       time.Now(),
	}

	tracker.Track("0x123", deployment)

	got := tracker.Get("0x123")
	if got == nil {
		t.Fatal("expected to get deployment, got nil")
	}
	if got.TxHash != "0x123" {
		t.Errorf("expected TxHash '0x123', got '%s'", got.TxHash)
	}
	if got.OrgID != "org1" {
		t.Errorf("expected OrgID 'org1', got '%s'", got.OrgID)
	}
	if !got.IsPlainCreate {
		t.Error("expected IsPlainCreate to be true")
	}
	if got.PreRegisteredAddr != "0xabc" {
		t.Errorf("expected PreRegisteredAddr '0xabc', got '%s'", got.PreRegisteredAddr)
	}
}

func TestPendingDeploymentTracker_GetRemovesEntry(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	deployment := &PendingDeployment{
		TxHash:      "0x456",
		OrgID:       "org1",
		SubmittedAt: time.Now(),
	}

	tracker.Track("0x456", deployment)

	// First Get should return the deployment
	got := tracker.Get("0x456")
	if got == nil {
		t.Fatal("expected to get deployment on first Get")
	}

	// Second Get should return nil (entry was removed)
	got = tracker.Get("0x456")
	if got != nil {
		t.Error("expected nil on second Get, entry should have been removed")
	}
}

func TestPendingDeploymentTracker_GetNonExistent(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	// Get non-existent entry
	got := tracker.Get("0xnonexistent")
	if got != nil {
		t.Error("expected nil for non-existent entry")
	}
}

func TestPendingDeploymentTracker_Peek(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	deployment := &PendingDeployment{
		TxHash:      "0x789",
		OrgID:       "org1",
		SubmittedAt: time.Now(),
	}

	tracker.Track("0x789", deployment)

	// Peek should return the deployment
	got := tracker.Peek("0x789")
	if got == nil {
		t.Fatal("expected to peek deployment")
	}

	// Peek again should still return it (not removed)
	got = tracker.Peek("0x789")
	if got == nil {
		t.Fatal("expected to peek deployment again (should not be removed)")
	}

	// Get should still work
	got = tracker.Get("0x789")
	if got == nil {
		t.Fatal("expected Get to work after Peek")
	}
}

func TestPendingDeploymentTracker_Remove(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	deployment := &PendingDeployment{
		TxHash:      "0xabc",
		OrgID:       "org1",
		SubmittedAt: time.Now(),
	}

	tracker.Track("0xabc", deployment)

	// Remove it
	tracker.Remove("0xabc")

	// Should be gone
	got := tracker.Get("0xabc")
	if got != nil {
		t.Error("expected nil after Remove")
	}
}

func TestPendingDeploymentTracker_Cleanup(t *testing.T) {
	// Use a very short max age for testing
	tracker := NewPendingDeploymentTracker(50 * time.Millisecond)

	// Add an old deployment
	oldDeployment := &PendingDeployment{
		TxHash:      "0xold",
		OrgID:       "org1",
		SubmittedAt: time.Now().Add(-100 * time.Millisecond), // Already expired
	}
	tracker.Track("0xold", oldDeployment)

	// Add a new deployment
	newDeployment := &PendingDeployment{
		TxHash:      "0xnew",
		OrgID:       "org1",
		SubmittedAt: time.Now(),
	}
	tracker.Track("0xnew", newDeployment)

	// Cleanup should remove the old one
	removed := tracker.Cleanup()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	// Old should be gone
	if tracker.Peek("0xold") != nil {
		t.Error("expected old deployment to be removed")
	}

	// New should still exist
	if tracker.Peek("0xnew") == nil {
		t.Error("expected new deployment to still exist")
	}
}

func TestPendingDeploymentTracker_CleanupRemovesAllExpired(t *testing.T) {
	tracker := NewPendingDeploymentTracker(50 * time.Millisecond)

	// Add multiple expired deployments
	for i := 0; i < 5; i++ {
		deployment := &PendingDeployment{
			TxHash:      string(rune('a' + i)),
			OrgID:       "org1",
			SubmittedAt: time.Now().Add(-100 * time.Millisecond),
		}
		tracker.Track(deployment.TxHash, deployment)
	}

	// Add one valid deployment
	validDeployment := &PendingDeployment{
		TxHash:      "valid",
		OrgID:       "org1",
		SubmittedAt: time.Now(),
	}
	tracker.Track("valid", validDeployment)

	// Size should be 6
	if tracker.Size() != 6 {
		t.Errorf("expected size 6, got %d", tracker.Size())
	}

	// Cleanup
	removed := tracker.Cleanup()
	if removed != 5 {
		t.Errorf("expected 5 removed, got %d", removed)
	}

	// Size should now be 1
	if tracker.Size() != 1 {
		t.Errorf("expected size 1 after cleanup, got %d", tracker.Size())
	}
}

func TestPendingDeploymentTracker_Size(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	if tracker.Size() != 0 {
		t.Errorf("expected initial size 0, got %d", tracker.Size())
	}

	tracker.Track("0x1", &PendingDeployment{TxHash: "0x1", SubmittedAt: time.Now()})
	tracker.Track("0x2", &PendingDeployment{TxHash: "0x2", SubmittedAt: time.Now()})
	tracker.Track("0x3", &PendingDeployment{TxHash: "0x3", SubmittedAt: time.Now()})

	if tracker.Size() != 3 {
		t.Errorf("expected size 3, got %d", tracker.Size())
	}

	tracker.Get("0x1") // Remove one

	if tracker.Size() != 2 {
		t.Errorf("expected size 2 after Get, got %d", tracker.Size())
	}
}

func TestPendingDeploymentTracker_Clear(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	tracker.Track("0x1", &PendingDeployment{TxHash: "0x1", SubmittedAt: time.Now()})
	tracker.Track("0x2", &PendingDeployment{TxHash: "0x2", SubmittedAt: time.Now()})

	if tracker.Size() != 2 {
		t.Errorf("expected size 2 before clear, got %d", tracker.Size())
	}

	tracker.Clear()

	if tracker.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", tracker.Size())
	}
}

func TestPendingDeploymentTracker_TrackOverwrite(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	deployment1 := &PendingDeployment{
		TxHash:      "0x123",
		OrgID:       "org1",
		SubmittedAt: time.Now(),
	}
	tracker.Track("0x123", deployment1)

	// Track with same hash but different data
	deployment2 := &PendingDeployment{
		TxHash:      "0x123",
		OrgID:       "org2",
		SubmittedAt: time.Now(),
	}
	tracker.Track("0x123", deployment2)

	// Should get the new one
	got := tracker.Get("0x123")
	if got == nil {
		t.Fatal("expected to get deployment")
	}
	if got.OrgID != "org2" {
		t.Errorf("expected OrgID 'org2', got '%s'", got.OrgID)
	}
}

func TestPendingDeploymentTracker_NilAndEmptyHandling(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	// Track with empty hash should be no-op
	tracker.Track("", &PendingDeployment{TxHash: "", SubmittedAt: time.Now()})
	if tracker.Size() != 0 {
		t.Error("expected empty hash to be ignored")
	}

	// Track with nil deployment should be no-op
	tracker.Track("0x123", nil)
	if tracker.Size() != 0 {
		t.Error("expected nil deployment to be ignored")
	}

	// Get with empty hash should return nil
	got := tracker.Get("")
	if got != nil {
		t.Error("expected Get with empty hash to return nil")
	}

	// Peek with empty hash should return nil
	got = tracker.Peek("")
	if got != nil {
		t.Error("expected Peek with empty hash to return nil")
	}
}

func TestPendingDeploymentTracker_ThreadSafety(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	const numGoroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 4)

	// Concurrent Track
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				hash := string(rune(workerID*1000 + j))
				tracker.Track(hash, &PendingDeployment{
					TxHash:      hash,
					OrgID:       "org1",
					SubmittedAt: time.Now(),
				})
			}
		}(i)
	}

	// Concurrent Get
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				hash := string(rune(workerID*1000 + j))
				tracker.Get(hash)
			}
		}(i)
	}

	// Concurrent Peek
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				hash := string(rune(workerID*1000 + j))
				tracker.Peek(hash)
			}
		}(i)
	}

	// Concurrent Cleanup
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine/10; j++ {
				tracker.Cleanup()
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
		// Success - no data race or deadlock
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out - possible deadlock")
	}
}

func TestPendingDeploymentTracker_ThreadSafetyWithSize(t *testing.T) {
	tracker := NewPendingDeploymentTracker(1 * time.Hour)

	const numGoroutines = 20
	const opsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3)

	// Concurrent Track
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				hash := string(rune(workerID*1000 + j))
				tracker.Track(hash, &PendingDeployment{
					TxHash:      hash,
					OrgID:       "org1",
					SubmittedAt: time.Now(),
				})
			}
		}(i)
	}

	// Concurrent Get and Size
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				hash := string(rune(workerID*1000 + j))
				tracker.Get(hash)
				tracker.Size() // Should not deadlock with Get
			}
		}(i)
	}

	// Concurrent Clear
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine/10; j++ {
				tracker.Clear()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out - possible deadlock")
	}
}
