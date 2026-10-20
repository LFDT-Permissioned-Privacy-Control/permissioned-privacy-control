// Package version holds the build identity of the privacy-proxy binary.
//
// The three vars below are populated at build time via the linker:
//
//	go build -ldflags "\
//	  -X privacy-proxy/internal/version.Version=$(git describe --tags --always --dirty) \
//	  -X privacy-proxy/internal/version.Commit=$(git rev-parse --short HEAD) \
//	  -X privacy-proxy/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// The Makefile and Dockerfile.backend wire these in (see RD-1023). A plain
// `go build` with no ldflags leaves the "dev" defaults — that's intentional,
// so a developer build is obviously distinguishable from a released one and
// nothing panics when the flags are absent.
package version

import "fmt"

// These are overwritten by -ldflags at build time. Keep them as plain string
// vars (not consts) so the linker's -X can reach them.
var (
	// Version is the release identity, normally `git describe --tags`
	// (e.g. "v0.9.1" or "v0.9.1-3-gabc1234-dirty"). "dev" for an
	// un-stamped local build.
	Version = "dev"
	// Commit is the short git SHA the binary was built from.
	Commit = "none"
	// BuildTime is the UTC build timestamp in RFC3339 (e.g.
	// "2026-06-01T10:00:00Z").
	BuildTime = "unknown"
)

// String renders the build identity for logs and human-facing output, e.g.
// "v0.9.1 (commit abc1234, built 2026-06-01T10:00:00Z)".
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuildTime)
}
