package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestActivityUpgradeCLIRequiresExplicitDrainAndConfiguredState(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(map[string]any{"version": 1, "root": root, "configured": false})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "private/state.json"), state, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"missing drain", []string{"upgrade-activity", "--root", root}, 2},
		{"false drain", []string{"upgrade-activity", "--root", root, "--drained=false"}, 2},
		{"unconfigured", []string{"upgrade-activity", "--root", root, "--drained"}, 1},
		{"missing root", []string{"upgrade-activity", "--drained"}, 1},
		{"wallet flag forbidden", []string{"upgrade-activity", "--root", root, "--drained", "--wallet-output", "/unused"}, 2},
		{"drain flag wrong command", []string{"configure", "--root", root, "--drained"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
	after, err := os.ReadFile(filepath.Join(root, "private/state.json"))
	if err != nil || string(after) != string(state) {
		t.Fatal("rejected commands mutated demo state", err)
	}
}
