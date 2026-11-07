package historynamespace

import (
	"crypto/sha256"
	"io"
	"os"
	"syscall"
)

// ReadApprovedArtifact reads one pinned local regular file. It neither fetches
// Git nor infers approval: expected must come from the trusted operator/CI input.
func ReadApprovedArtifact(path string, expected Digest) (*Artifact, error) {
	if path == "" || len(path) > 4096 || expected == (Digest{}) {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	if before.Size() <= 0 || before.Size() > MaxArtifactBytes {
		return nil, ErrTooBroad
	}
	// NONBLOCK also closes the Lstat/open replacement-to-FIFO blocking window.
	f, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxArtifactBytes+1))
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(raw) > MaxArtifactBytes {
		return nil, ErrTooBroad
	}
	after, err := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !after.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) || opened.Size() != int64(len(raw)) || after.Size() != int64(len(raw)) || Digest(sha256.Sum256(raw)) != expected {
		return nil, ErrUnavailable
	}
	return ParseArtifact(raw)
}
