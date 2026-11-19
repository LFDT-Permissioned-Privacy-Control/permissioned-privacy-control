package v2demo

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateNetworkFixtureCannotConvertExistingHostState(t *testing.T) {
	for _, private := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "state")
		if err := initState(root, private); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(filepath.Join(root, "private/state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := initState(root, !private); err != ErrInvalid {
			t.Fatalf("mode conversion was not rejected: %v", err)
		}
		after, err := os.ReadFile(filepath.Join(root, "private/state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("rejected network conversion changed existing identities or state")
		}
	}
}
