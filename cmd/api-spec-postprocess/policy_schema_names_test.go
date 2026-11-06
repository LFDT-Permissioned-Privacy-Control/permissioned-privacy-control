package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func policySchemaFixture() map[string]any {
	schemas := map[string]any{"unrelated.Model": map[string]any{"type": "string", "enum": []any{"keep", "these"}}}
	for source, target := range policySchemaNames {
		schemas[source] = map[string]any{"type": "object", "description": target,
			"properties": map[string]any{"next": map[string]any{"$ref": schemaRefPrefix + "privacy-proxy_internal_policycore.AddressMatch"}}}
	}
	return map[string]any{"components": map[string]any{"schemas": schemas}, "paths": map[string]any{
		"/unchanged": map[string]any{"description": schemaRefPrefix + "privacy-proxy_internal_policycore.Binding",
			"parameters": []any{map[string]any{"$ref": schemaRefPrefix + "privacy-proxy_internal_policycore.Binding"}},
			"external":   map[string]any{"$ref": "https://external.example/spec" + schemaRefPrefix + "privacy-proxy_internal_policycore.Binding"}},
	}}
}

func copyDocument(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPolicySchemaNamesPreserveContractAndAreIdempotent(t *testing.T) {
	doc := policySchemaFixture()
	if err := normalizePolicySchemaNames(doc); err != nil {
		t.Fatal(err)
	}
	schemas, _ := dig[map[string]any](doc, "components", "schemas")
	for source, target := range policySchemaNames {
		if _, exists := schemas[source]; exists {
			t.Errorf("new implementation name leaked: %s", source)
		}
		if _, exists := schemas[target]; !exists {
			t.Errorf("public name disappeared: %s", target)
		}
	}
	route, _ := dig[map[string]any](doc, "paths", "/unchanged")
	if route["description"] != schemaRefPrefix+"privacy-proxy_internal_policycore.Binding" {
		t.Fatal("non-reference string changed")
	}
	if route["external"].(map[string]any)["$ref"] != "https://external.example/spec"+schemaRefPrefix+"privacy-proxy_internal_policycore.Binding" {
		t.Fatal("external reference changed")
	}
	if route["parameters"].([]any)[0].(map[string]any)["$ref"] != schemaRefPrefix+"privacy-proxy_internal_policydsl.Binding" {
		t.Fatal("internal reference did not follow the public schema")
	}
	if !reflect.DeepEqual(schemas["unrelated.Model"], map[string]any{"type": "string", "enum": []any{"keep", "these"}}) {
		t.Fatal("unrelated schema changed")
	}
	before := copyDocument(t, doc)
	if err := normalizePolicySchemaNames(doc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, doc) {
		t.Fatal("second normalization changed the document")
	}
}

func TestPolicySchemaNamesRequireEquivalentDuplicates(t *testing.T) {
	const source = "privacy-proxy_internal_policycore.FrameRule"
	const target = "privacy-proxy_internal_policydsl.FrameRule"
	for _, conflict := range []bool{false, true} {
		doc := policySchemaFixture()
		schemas, _ := dig[map[string]any](doc, "components", "schemas")
		schemas[target] = copyDocument(t, schemas[source].(map[string]any))
		// Equal definitions may initially spell the reference differently.
		schemas[target].(map[string]any)["properties"].(map[string]any)["next"].(map[string]any)["$ref"] = schemaRefPrefix + "privacy-proxy_internal_policydsl.AddressMatch"
		if conflict {
			schemas[target].(map[string]any)["required"] = []any{"a-new-requirement"}
		}
		err := normalizePolicySchemaNames(doc)
		if conflict && err == nil {
			t.Fatal("conflicting schema was silently overwritten")
		}
		if !conflict && err != nil {
			t.Fatal(err)
		}
	}
}

func TestPolicySchemaNamesRejectMissingOrUnmappedDefinitions(t *testing.T) {
	for _, mode := range []string{"missing", "unknown-schema", "unknown-ref"} {
		t.Run(mode, func(t *testing.T) {
			doc := policySchemaFixture()
			schemas, _ := dig[map[string]any](doc, "components", "schemas")
			switch mode {
			case "missing":
				delete(schemas, "privacy-proxy_internal_policycore.Binding")
			case "unknown-schema":
				schemas["privacy-proxy_internal_policycore.Unreviewed"] = map[string]any{"type": "object"}
			case "unknown-ref":
				doc["unreviewed"] = map[string]any{"$ref": schemaRefPrefix + "privacy-proxy_internal_policybackend_evm.Unreviewed"}
			}
			if err := normalizePolicySchemaNames(doc); err == nil {
				t.Fatal("schema drift was silently accepted")
			}
		})
	}
}

func TestPolicySchemaNamesYAMLPreserveMeaningAndFormatting(t *testing.T) {
	doc := policySchemaFixture()
	schemas, _ := dig[map[string]any](doc, "components", "schemas")
	schemas["privacy-proxy_internal_policydsl.FrameRule"] = copyDocument(t, schemas["privacy-proxy_internal_policycore.FrameRule"].(map[string]any))
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		t.Fatal(err)
	}
	input := strings.Split(buf.String(), "\n")
	output, err := normalizePolicySchemaNamesYAML(input)
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(output, "\n")), &actual); err != nil {
		t.Fatal(err)
	}
	if err := normalizePolicySchemaNames(doc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, doc) {
		t.Fatal("YAML normalization changed schema semantics")
	}
	again, err := normalizePolicySchemaNamesYAML(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(output, "\n") != strings.Join(again, "\n") {
		t.Fatal("YAML normalization is not byte-idempotent")
	}
	// A conflicting alias must also be rejected through the YAML entrypoint.
	schemas["privacy-proxy_internal_policycore.FrameRule"] = map[string]any{"type": "integer"}
	buf.Reset()
	if err := encoder.Encode(doc); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizePolicySchemaNamesYAML(strings.Split(buf.String(), "\n")); err == nil {
		t.Fatal("YAML accepted a conflicting alias")
	}
}
