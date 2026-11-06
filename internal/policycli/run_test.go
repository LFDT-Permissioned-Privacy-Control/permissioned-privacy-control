package policycli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycli"
)

func source(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir("../../examples/ops-v2-policy")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join("../../examples/ops-v2-policy", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestABICommandReadsBoundedRegularFileAndReportsExactDigest(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "contract.json")
	raw := []byte(`[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}]}]`)
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := invoke(t, t.Context(), "policy", "abi", "--file", name)
	var result policybundle.ABIInspection
	if code != 0 || len(errs) != 0 || json.Unmarshal(out, &result) != nil || result.FileByteDigest != policybundle.RawDigest(raw) || len(result.Functions) != 1 || result.Functions[0].Selector != "0xa9059cbb" || result.DeploymentVerified {
		t.Fatalf("incorrect ABI command report: %s %s", out, errs)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{dir, link, filepath.Join(dir, "missing")} {
		code, out, errs := invoke(t, t.Context(), "policy", "abi", "--file", input)
		if code == 0 || len(out) != 0 || !json.Valid(errs) {
			t.Fatal("nonregular input accepted")
		}
	}
	if err := os.WriteFile(name, bytes.Repeat([]byte(" "), int(policybundle.DefaultLimits().MaxDocumentBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = invoke(t, t.Context(), "policy", "abi", "--file", name)
	if code == 0 || len(out) != 0 || !json.Valid(errs) {
		t.Fatal("oversize ABI accepted")
	}
}

func invoke(t *testing.T, ctx context.Context, args ...string) (int, []byte, []byte) {
	t.Helper()
	var out, errs bytes.Buffer
	code := policycli.Run(ctx, args, &out, &errs)
	return code, out.Bytes(), errs.Bytes()
}

func TestPrepareCheckInspectUseExactNewArtifact(t *testing.T) {
	draft := source(t)
	output := filepath.Join(t.TempDir(), "artifact")
	code, raw, errs := invoke(t, t.Context(), "policy", "prepare", "--source", draft, "--output", output, "--profile", "catalog-foundation/v1")
	if code != 0 || len(errs) != 0 {
		t.Fatalf("prepare failed: %s", errs)
	}
	var prepared policycli.Report
	if err := json.Unmarshal(raw, &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.Approved || !prepared.Profile.ValidationOnly || prepared.Action != "prepare" {
		t.Fatal("proposal advertised approval or runtime readiness")
	}
	for _, command := range []string{"check", "inspect"} {
		code, raw, errs = invoke(t, t.Context(), "policy", command, "--bundle", output, "--expected-digest", string(prepared.ManifestDigest), "--environment", "local", "--chain-id", "31337", "--profile", "catalog-foundation/v1")
		if code != 0 || len(errs) != 0 {
			t.Fatalf("%s failed: %s", command, errs)
		}
		var report policycli.Report
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		if report.ManifestDigest != prepared.ManifestDigest || report.Approved {
			t.Fatal("check changed selection or claimed approval")
		}
	}
	groupPath := filepath.Join(output, "groups.json")
	original, err := os.ReadFile(groupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groupPath, append(original, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	code, raw, errs = invoke(t, t.Context(), "policy", "check", "--bundle", output, "--expected-digest", string(prepared.ManifestDigest), "--environment", "local", "--chain-id", "31337", "--profile", "catalog-foundation/v1")
	if code == 0 || len(raw) != 0 || len(errs) == 0 {
		t.Fatal("tampered output passed pinned check")
	}
}

func TestPrepareNeverOverwritesExistingDirectory(t *testing.T) {
	draft := source(t)
	output := t.TempDir()
	marker := filepath.Join(output, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := invoke(t, t.Context(), "policy", "prepare", "--source", draft, "--output", output, "--profile", "catalog-foundation/v1")
	if code == 0 || len(out) != 0 {
		t.Fatal("existing output directory accepted")
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 1 {
		t.Fatal("existing directory modified")
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "keep" {
		t.Fatal("existing content lost")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	output = filepath.Join(t.TempDir(), "canceled")
	code, out, _ = invoke(t, ctx, "policy", "prepare", "--source", draft, "--output", output, "--profile", "catalog-foundation/v1")
	if code == 0 || len(out) != 0 {
		t.Fatal("canceled preparation reported success")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("canceled input created output")
	}
}

func TestFailedInputCannotReportOrWriteAnArtifact(t *testing.T) {
	draft := source(t)
	if err := os.WriteFile(filepath.Join(draft, "groups.json"), []byte(`{"groups":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "invalid")
	code, out, errs := invoke(t, t.Context(), "policy", "prepare", "--source", draft, "--output", output, "--profile", "catalog-foundation/v1")
	if code == 0 || len(out) != 0 || !json.Valid(errs) {
		t.Fatal("invalid source did not produce only a JSON error")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("invalid source wrote output")
	}
	for _, args := range [][]string{{"policy", "prepare"}, {"policy", "check", "--profile", "catalog-foundation/v1"}, {"policy", "activate"}, {"policy", "profiles", "extra"}} {
		code, out, _ := invoke(t, t.Context(), args...)
		if code == 0 || len(out) != 0 {
			t.Fatalf("invalid command accepted: %v", args)
		}
	}
}
