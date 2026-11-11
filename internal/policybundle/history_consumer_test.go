package policybundle_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycli"
	"privacy-proxy/internal/policyprofiles"
)

func historyFixture(t *testing.T) fixture {
	f := creationObservedFixture(t)
	f.options.Profile = policybundle.RuntimeCreationObservedHistoryProfile("rpc-test/v1")
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityRuntimeHistory)
	return f
}
func TestHistoryConsumerExplicitRequirementsAndOldDocumentIdentity(t *testing.T) {
	old := load(t, creationObservedFixture(t))
	f := historyFixture(t)
	history := load(t, f)
	if old.HistoryConsumerEnabled() || !history.HistoryConsumerEnabled() || !slices.Contains(history.Requirements().Capabilities, policybundle.CapabilityRuntimeHistory) {
		t.Fatal("marker or approved requirement missing")
	}
	if !reflect.DeepEqual(old.Metadata().Documents, history.Metadata().Documents) || old.Metadata().ManifestDigest == history.Metadata().ManifestDigest {
		t.Fatal("false registry document drift or missing deliberate approved manifest delta")
	}
	f = historyFixture(t)
	f.edit(t, "registry.json", func(d map[string]any) { contract(d)["allowVisibleToUnlock"] = true })
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityVisibleToHistory)
	enabled := load(t, f)
	if !enabled.HistoryConsumerEnabled() || !slices.Contains(enabled.Requirements().Capabilities, policybundle.CapabilityVisibleToHistory) {
		t.Fatal("approved optional unlock capability lost")
	}
	if reflect.DeepEqual(history.Metadata().Documents, enabled.Metadata().Documents) {
		t.Fatal("true flag not bound by canonical/raw registry identity")
	}
	for _, mode := range []string{"missing-runtime", "missing-unlock", "default-profile", "self-declared-under-default", "absent-required-flag"} {
		t.Run(mode, func(t *testing.T) {
			f := historyFixture(t)
			switch mode {
			case "missing-runtime":
				f.manifest.RequiredCapabilities = slices.DeleteFunc(f.manifest.RequiredCapabilities, func(s string) bool { return s == policybundle.CapabilityRuntimeHistory })
			case "missing-unlock":
				f.edit(t, "registry.json", func(d map[string]any) { contract(d)["allowVisibleToUnlock"] = true })
			case "default-profile":
				f.options.Profile = policybundle.RuntimeCreationObservedProfile("rpc-test/v1")
				f.edit(t, "registry.json", func(d map[string]any) { contract(d)["allowVisibleToUnlock"] = true })
			case "self-declared-under-default":
				f.options.Profile = policybundle.RuntimeCreationObservedProfile("rpc-test/v1")
			case "absent-required-flag":
				f.edit(t, "registry.json", func(d map[string]any) { delete(contract(d), "allowVisibleToUnlock") })
			}
			reject(t, f.write(t), f.options, t.Context())
		})
	}
}

func TestHistoryConsumerTrustedCLIActualPrepareAndCheck(t *testing.T) {
	f := creationObservedFixture(t)
	options, _, err := policyprofiles.HistoryOptions(policybundle.RuntimeCreationObservedProfileID)
	if err != nil {
		t.Fatal(err)
	}
	f.options = options
	f.edit(t, "groups.json", func(d map[string]any) {
		spec := d["spec"].(map[string]any)
		for _, raw := range spec["groups"].([]any) {
			raw.(map[string]any)["allowedMethods"] = append([]string{}, options.Methods.Assignable...)
		}
	})
	f.edit(t, "registry.json", func(d map[string]any) { contract(d)["allowVisibleToUnlock"] = true })
	selection := writeDraft(t, f, draftFor(f))
	output := filepath.Join(t.TempDir(), "prepared-history")
	var stdout, stderr bytes.Buffer
	code := policycli.Run(t.Context(), []string{"policy", "prepare", "--profile", policybundle.RuntimeCreationObservedProfileID, "--consumer", "history", "--source", selection.Directory, "--output", output}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("actual history CLI prepare code%d %s", code, stderr.String())
	}
	var report policycli.Report
	if json.Unmarshal(stdout.Bytes(), &report) != nil || !slices.Contains(report.Requirements.Capabilities, policybundle.CapabilityRuntimeHistory) || !slices.Contains(report.Requirements.Capabilities, policybundle.CapabilityVisibleToHistory) {
		t.Fatal("CLI did not use explicit compiled consumer", stdout.String())
	}
	args := []string{"policy", "check", "--profile", policybundle.RuntimeCreationObservedProfileID, "--bundle", output, "--expected-digest", string(report.ManifestDigest), "--environment", report.Metadata.Environment, "--chain-id", report.Metadata.ChainID}
	stdout.Reset()
	stderr.Reset()
	if code := policycli.Run(t.Context(), args, &stdout, &stderr); code == 0 {
		t.Fatal("default helper silently accepted history-required artifact")
	}
	args = append(args, "--consumer", "history")
	stdout.Reset()
	stderr.Reset()
	if code := policycli.Run(t.Context(), args, &stdout, &stderr); code != 0 {
		t.Fatal("matching explicit server/tool selection failed", code, stderr.String())
	}
	for _, id := range []string{policybundle.FoundationProfileID, policybundle.RuntimeCallProfileID, "auto"} {
		if _, _, err := policyprofiles.HistoryOptions(id); err == nil {
			t.Fatal("wrong profile selected history", id)
		}
	}
}
