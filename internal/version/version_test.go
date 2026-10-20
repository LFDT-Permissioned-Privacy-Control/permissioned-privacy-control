package version

import (
	"strings"
	"testing"
)

// The vars are overwritten by -ldflags in real builds. In `go test` (no
// ldflags) they hold the dev defaults — assert those are sane and that
// String() composes them in the documented shape.

func TestDefaults(t *testing.T) {
	if Version == "" {
		t.Error("Version default must be non-empty (a plain build should read 'dev', never empty)")
	}
	if Commit == "" {
		t.Error("Commit default must be non-empty")
	}
	if BuildTime == "" {
		t.Error("BuildTime default must be non-empty")
	}
	if Version != "dev" {
		t.Errorf("Version default = %q, want %q (test binary is built without -ldflags)", Version, "dev")
	}
}

func TestString(t *testing.T) {
	// Save/restore so we don't disturb other tests in the package.
	origV, origC, origB := Version, Commit, BuildTime
	t.Cleanup(func() { Version, Commit, BuildTime = origV, origC, origB })

	Version = "v9.9.9"
	Commit = "abc1234"
	BuildTime = "2026-06-01T10:00:00Z"

	got := String()
	want := "v9.9.9 (commit abc1234, built 2026-06-01T10:00:00Z)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	// Sanity: every component must appear so logs/CLI never drop a field.
	for _, part := range []string{Version, Commit, BuildTime} {
		if !strings.Contains(got, part) {
			t.Errorf("String() = %q is missing component %q", got, part)
		}
	}
}
