package main

import (
	"testing"
	"time"
)

func TestConfirmationEngine_RequestAndValidate(t *testing.T) {
	e := NewConfirmationEngine()

	params := map[string]any{"org_id": "abc-123"}
	token := e.Request("delete_org", params)

	if token == "" {
		t.Fatal("expected non-empty token")
	}

	got, err := e.Validate(token, "delete_org")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["org_id"] != "abc-123" {
		t.Fatalf("expected org_id abc-123, got %v", got["org_id"])
	}
}

func TestConfirmationEngine_TokenConsumedOnUse(t *testing.T) {
	e := NewConfirmationEngine()

	token := e.Request("delete_org", map[string]any{"org_id": "x"})

	_, err := e.Validate(token, "delete_org")
	if err != nil {
		t.Fatalf("first validate should succeed: %v", err)
	}

	_, err = e.Validate(token, "delete_org")
	if err == nil {
		t.Fatal("second validate should fail — token consumed")
	}
}

func TestConfirmationEngine_WrongTool(t *testing.T) {
	e := NewConfirmationEngine()

	token := e.Request("delete_org", map[string]any{})

	_, err := e.Validate(token, "delete_user")
	if err == nil {
		t.Fatal("expected error for wrong tool name")
	}
}

func TestConfirmationEngine_InvalidToken(t *testing.T) {
	e := NewConfirmationEngine()

	_, err := e.Validate("bogus-token", "delete_org")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestConfirmationEngine_Expiry(t *testing.T) {
	e := NewConfirmationEngine()
	e.ttl = 10 * time.Millisecond

	token := e.Request("delete_org", map[string]any{})

	time.Sleep(50 * time.Millisecond)

	_, err := e.Validate(token, "delete_org")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestConfirmationEngine_MultipleTokensIndependent(t *testing.T) {
	e := NewConfirmationEngine()

	t1 := e.Request("delete_org", map[string]any{"id": "1"})
	t2 := e.Request("delete_user", map[string]any{"id": "2"})

	p2, err := e.Validate(t2, "delete_user")
	if err != nil {
		t.Fatalf("t2 should validate: %v", err)
	}
	if p2["id"] != "2" {
		t.Fatalf("expected id 2, got %v", p2["id"])
	}

	p1, err := e.Validate(t1, "delete_org")
	if err != nil {
		t.Fatalf("t1 should still validate: %v", err)
	}
	if p1["id"] != "1" {
		t.Fatalf("expected id 1, got %v", p1["id"])
	}
}
