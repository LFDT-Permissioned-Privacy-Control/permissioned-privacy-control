package policycli_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBrowserPackageUnpacksExactBytesIntoNewSourceRoot(t *testing.T) {
	input := source(t)
	entries, err := os.ReadDir(input)
	if err != nil {
		t.Fatal(err)
	}
	files := []map[string]string{}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(input, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, map[string]string{"path": entry.Name(), "dataBase64": base64.StdEncoding.EncodeToString(raw)})
	}
	packageFile := filepath.Join(t.TempDir(), "proposal.json")
	encoded, _ := json.Marshal(map[string]any{"apiVersion": "ops.ui-source-package/v1", "roots": []any{map[string]any{"id": "core", "files": files}}})
	if err := os.WriteFile(packageFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "sources")
	code, raw, errs := invoke(t, t.Context(), "policy", "unpack", "--file", packageFile, "--output", output)
	if code != 0 || len(errs) != 0 || !json.Valid(raw) {
		t.Fatalf("unpack failed: %s %s", raw, errs)
	}
	for _, file := range files {
		got, err := os.ReadFile(filepath.Join(output, "core", file["path"]))
		want, _ := base64.StdEncoding.DecodeString(file["dataBase64"])
		if err != nil || string(got) != string(want) {
			t.Fatal("source bytes changed", file["path"], err)
		}
	}
	artifact := filepath.Join(t.TempDir(), "artifact")
	code, _, errs = invoke(t, t.Context(), "policy", "prepare", "--source", filepath.Join(output, "core"), "--output", artifact, "--profile", "catalog-foundation/v1")
	if code != 0 {
		t.Fatalf("unpacked browser source fails actual Go preparation: %s", errs)
	}
	code, _, _ = invoke(t, t.Context(), "policy", "unpack", "--file", packageFile, "--output", output)
	if code == 0 {
		t.Fatal("unpack overwrote an existing source directory")
	}
}

func TestBrowserPackageRejectsDuplicateTraversalOrInvalidEncodingBeforeWriting(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"traversal", `{"apiVersion":"ops.ui-source-package/v1","roots":[{"id":"core","files":[{"path":"../draft.json","dataBase64":"e30="}]}]}`},
		{"duplicate", `{"apiVersion":"ops.ui-source-package/v1","roots":[{"id":"core","files":[{"path":"draft.json","dataBase64":"e30="},{"path":"draft.json","dataBase64":"e30="}]}]}`},
		{"encoding", `{"apiVersion":"ops.ui-source-package/v1","roots":[{"id":"core","files":[{"path":"draft.json","dataBase64":"***"}]}]}`},
		{"duplicateJSON", `{"apiVersion":"ops.ui-source-package/v1","apiVersion":"ops.ui-source-package/v1","roots":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "source.json")
			if err := os.WriteFile(file, []byte(test.body), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "new-source")
			code, out, errs := invoke(t, t.Context(), "policy", "unpack", "--file", file, "--output", output)
			if code == 0 || len(out) != 0 || !json.Valid(errs) {
				t.Fatalf("invalid transport accepted: %s %s", out, errs)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("invalid transport created output")
			}
		})
	}
}
