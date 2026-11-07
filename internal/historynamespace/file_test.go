package historynamespace

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestApprovedFilePinning(t *testing.T) {
	raw := artifactBytes(t, finiteInput())
	pin := Digest(sha256.Sum256(raw))
	path := filepath.Join(t.TempDir(), "cohort.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadApprovedArtifact(path, pin); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadApprovedArtifact(link, pin); err == nil {
		t.Fatal("symlink source accepted")
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadApprovedArtifact(path, pin); err == nil {
		t.Fatal("changed exact approval bytes accepted")
	}
	if _, err := ReadApprovedArtifact(filepath.Dir(path), pin); err == nil {
		t.Fatal("directory source accepted")
	}
}
