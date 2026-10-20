package main

import (
	"testing"
)

func TestKvf(t *testing.T) {
	got := kvf("Status", "running")
	if got != "Status:                  running" {
		t.Fatalf("unexpected kvf output: %q", got)
	}
}

func TestSection(t *testing.T) {
	got := section("Test")
	if got != "## Test" {
		t.Fatalf("unexpected section: %q", got)
	}
}

func TestJoinLines_SkipsEmpty(t *testing.T) {
	got := joinLines("a", "", "b", "", "c")
	if got != "a\nb\nc" {
		t.Fatalf("unexpected joinLines: %q", got)
	}
}

func TestJoinLines_AllEmpty(t *testing.T) {
	got := joinLines("", "", "")
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestBoolYesNo(t *testing.T) {
	if boolYesNo(true) != "Yes" {
		t.Fatal("expected Yes")
	}
	if boolYesNo(false) != "No" {
		t.Fatal("expected No")
	}
}

func TestGetString(t *testing.T) {
	m := map[string]any{"name": "test", "count": 42}
	if getString(m, "name") != "test" {
		t.Fatal("expected test")
	}
	if getString(m, "missing") != "" {
		t.Fatal("expected empty for missing key")
	}
	if getString(m, "count") != "" {
		t.Fatal("expected empty for non-string value")
	}
}

func TestGetBool(t *testing.T) {
	m := map[string]any{"active": true, "name": "x"}
	if !getBool(m, "active") {
		t.Fatal("expected true")
	}
	if getBool(m, "missing") {
		t.Fatal("expected false for missing")
	}
	if getBool(m, "name") {
		t.Fatal("expected false for non-bool")
	}
}

func TestGetFloat(t *testing.T) {
	m := map[string]any{"latency": 42.5}
	if getFloat(m, "latency") != 42.5 {
		t.Fatal("expected 42.5")
	}
	if getFloat(m, "missing") != 0 {
		t.Fatal("expected 0 for missing")
	}
}

func TestGetMap(t *testing.T) {
	inner := map[string]any{"port": "8080"}
	m := map[string]any{"proxy": inner}
	got := getMap(m, "proxy")
	if got == nil || got["port"] != "8080" {
		t.Fatal("expected inner map")
	}
	if getMap(m, "missing") != nil {
		t.Fatal("expected nil for missing")
	}
}

func TestGetSlice(t *testing.T) {
	m := map[string]any{"items": []any{"a", "b"}}
	got := getSlice(m, "items")
	if len(got) != 2 {
		t.Fatal("expected 2 items")
	}
	if getSlice(m, "missing") != nil {
		t.Fatal("expected nil for missing")
	}
}

func TestPrettyJSON(t *testing.T) {
	got := prettyJSON(map[string]any{"a": 1})
	if got == "" {
		t.Fatal("expected non-empty JSON")
	}
}
