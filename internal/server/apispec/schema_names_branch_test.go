package apispec

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSchemaNameBaseRef(t *testing.T) {
	for _, tc := range []struct {
		name, event, target, want string
		wantErr                   bool
	}{
		{name: "main PR", event: "pull_request", target: "main", want: "origin/main"},
		{name: "master PR", event: "pull_request", target: "master", want: "origin/master"},
		{name: "release PR", event: "pull_request", target: "release/2.0", want: "origin/release/2.0"},
		{name: "missing PR target", event: "pull_request", wantErr: true},
		{name: "unknown release PR", event: "pull_request", target: "release/3.0", wantErr: true},
		{name: "unknown PR target", event: "pull_request", target: "feature/work", wantErr: true},
		{name: "local fallback", want: "origin/main"},
		{name: "push remains unchanged", event: "push", target: "release/2.0", want: "origin/main"},
		{name: "manual remains unchanged", event: "workflow_dispatch", target: "unknown", want: "origin/main"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := schemaNameBaseRef(tc.event, tc.target)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("schemaNameBaseRef(%q, %q) = %q, %v; want %q, error=%v", tc.event, tc.target, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// A schema published only on the release branch must remain protected after
// main diverges. Comparing this feature head against origin/main instead would
// find the original fork point, where the release-only schema did not exist.
func TestSchemaNameReleasePRCannotLaunderReleaseOnlyRemoval(t *testing.T) {
	t.Chdir(t.TempDir())
	runGit := func(args ...string) string {
		t.Helper()
		settings := []string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.name=Schema Fixture", "-c", "user.email=schema@example.invalid"}
		out, err := git(append(settings, args...)...)
		if err != nil {
			t.Fatalf("git %v: %s", args, gitReason(out, err))
		}
		return strings.TrimSpace(out)
	}
	writeBaseline := func(content string) {
		t.Helper()
		if err := os.WriteFile(baselinePath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		runGit("add", baselinePath)
		runGit("commit", "--quiet", "-m", "schema fixture")
	}
	runGit("init", "--quiet", "--initial-branch=main")
	writeBaseline("Common\n")
	fork := runGit("rev-parse", "HEAD")
	writeBaseline("Common\nReleaseOnly\n")
	runGit("update-ref", "refs/remotes/origin/release/2.0", "HEAD")
	writeBaseline("Common\n") // Feature head deletes schema and baseline entry.
	feature := runGit("rev-parse", "HEAD")
	runGit("checkout", "--quiet", "--detach", fork)
	writeBaseline("Common\nMainOnly\n")
	runGit("update-ref", "refs/remotes/origin/main", "HEAD")
	runGit("checkout", "--quiet", "--detach", feature)

	baseRef, err := schemaNameBaseRef("pull_request", "release/2.0")
	if err != nil {
		t.Fatal(err)
	}
	base, err := readAtBaseRev(baseRef, baselinePath)
	if err != nil || !base.found {
		t.Fatalf("release baseline lookup = %+v, %v", base, err)
	}
	baseNames := parseNameList([]byte(base.content))
	if baseNames["MainOnly"] {
		t.Fatal("future main schema contaminated the release baseline")
	}
	if got := droppedFromBaseline(baseNames, names("Common"), names()); !reflect.DeepEqual(got, []string{"ReleaseOnly"}) {
		t.Fatalf("release-only schema removal escaped review: %v", got)
	}

	oldBase, err := readAtBaseRev("origin/main", baselinePath)
	if err != nil || !oldBase.found {
		t.Fatalf("main baseline lookup = %+v, %v", oldBase, err)
	}
	if got := droppedFromBaseline(parseNameList([]byte(oldBase.content)), names("Common"), names()); len(got) != 0 {
		t.Fatalf("fixture should reproduce the old main-only blind spot, got %v", got)
	}
	if _, err := readAtBaseRev("origin/missing", baselinePath); err == nil {
		t.Fatal("an unavailable base must fail, not become an empty bootstrap baseline")
	}
}
