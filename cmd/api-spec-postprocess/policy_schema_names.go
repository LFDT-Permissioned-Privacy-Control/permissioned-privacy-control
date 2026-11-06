package main

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Swag follows the declaring package of nested aliased domain types. Keep the
// existing public names when moving their implementation behind the facade.
// This is a finite compatibility mapping, not a general package-prefix rewrite.
var policySchemaNames = map[string]string{
	"privacy-proxy_internal_policycore.AddressMatch":            "privacy-proxy_internal_policydsl.AddressMatch",
	"privacy-proxy_internal_policycore.AddressSource":           "privacy-proxy_internal_policydsl.AddressSource",
	"privacy-proxy_internal_policycore.ArgConstraint":           "privacy-proxy_internal_policydsl.ArgConstraint",
	"privacy-proxy_internal_policycore.Binding":                 "privacy-proxy_internal_policydsl.Binding",
	"privacy-proxy_internal_policycore.CallType":                "privacy-proxy_internal_policydsl.CallType",
	"privacy-proxy_internal_policycore.DeployerException":       "privacy-proxy_internal_policydsl.DeployerException",
	"privacy-proxy_internal_policycore.FrameRule":               "privacy-proxy_internal_policydsl.FrameRule",
	"privacy-proxy_internal_policycore.RecordPartyMatch":        "privacy-proxy_internal_policydsl.RecordPartyMatch",
	"privacy-proxy_internal_policybackend_evm.CompilerSettings": "privacy-proxy_internal_policydsl.CompilerSettings",
}

const schemaRefPrefix = "#/components/schemas/"

func movedPolicySchema(name string) bool {
	return strings.HasPrefix(name, "privacy-proxy_internal_policycore.") || strings.HasPrefix(name, "privacy-proxy_internal_policybackend_evm.")
}

func normalizedPolicyRef(ref string) (string, error) {
	if !strings.HasPrefix(ref, schemaRefPrefix) {
		return ref, nil
	}
	name := strings.TrimPrefix(ref, schemaRefPrefix)
	if target, ok := policySchemaNames[name]; ok {
		return schemaRefPrefix + target, nil
	}
	if movedPolicySchema(name) {
		return "", fmt.Errorf("unmapped policy schema reference %q", name)
	}
	return ref, nil
}

func normalizePolicyRefs(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if key == "$ref" {
				if ref, ok := item.(string); ok {
					normalized, err := normalizedPolicyRef(ref)
					if err != nil {
						return err
					}
					v[key] = normalized
				}
			} else if err := normalizePolicyRefs(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := normalizePolicyRefs(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizePolicySchemaNames(doc map[string]any) error {
	schemas, err := dig[map[string]any](doc, "components", "schemas")
	if err != nil {
		return err
	}
	for name := range schemas {
		if movedPolicySchema(name) {
			if _, known := policySchemaNames[name]; !known {
				return fmt.Errorf("unmapped policy schema %q", name)
			}
		}
	}
	if err := normalizePolicyRefs(doc); err != nil {
		return err
	}
	for source, target := range policySchemaNames {
		value, hasSource := schemas[source]
		existing, hasTarget := schemas[target]
		if !hasSource && !hasTarget {
			return fmt.Errorf("missing policy schema %q or %q", source, target)
		}
		if !hasSource {
			continue
		} // Already normalized; safe to run twice.
		if hasTarget && !reflect.DeepEqual(value, existing) {
			return fmt.Errorf("conflicting policy schemas %q and %q", source, target)
		}
		schemas[target] = value
		delete(schemas, source)
	}
	return nil
}

// Normalize only schema blocks and exact $ref lines in Swag's fixed layout.
// Parsing before/after checks structural equality without re-encoding the YAML
// and rewriting unrelated descriptions, sequences or request/response content.
func normalizePolicySchemaNamesYAML(lines []string) ([]string, error) {
	var expected map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &expected); err != nil {
		return nil, err
	}
	if err := normalizePolicySchemaNames(expected); err != nil {
		return nil, err
	}
	start := -1
	for i, line := range lines {
		if line == "  schemas:" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("missing YAML component schemas")
	}
	end := start
	for end < len(lines) && (strings.TrimSpace(lines[end]) == "" || strings.HasPrefix(lines[end], "    ")) {
		end++
	}
	blocks := map[string][]string{}
	for i := start; i < end; {
		line := lines[i]
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") || !strings.HasSuffix(line, ":") {
			return nil, fmt.Errorf("unexpected YAML schema block at line %d", i+1)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(line, "    "), ":")
		j := i + 1
		for j < end && (strings.TrimSpace(lines[j]) == "" || strings.HasPrefix(lines[j], "     ")) {
			j++
		}
		target := name
		if mapped, ok := policySchemaNames[name]; ok {
			target = mapped
		}
		block := append([]string(nil), lines[i:j]...)
		block[0] = "    " + target + ":"
		// Prefer the facade's original text when equal definitions coexist.
		// normalizePolicySchemaNames already rejected unequal duplicates.
		if _, exists := blocks[target]; !exists || name == target {
			blocks[target] = block
		}
		i = j
	}
	names := make([]string, 0, len(blocks))
	for name := range blocks {
		names = append(names, name)
	}
	sort.Strings(names)
	out := append([]string(nil), lines[:start]...)
	for _, name := range names {
		out = append(out, blocks[name]...)
	}
	out = append(out, lines[end:]...)
	for i, line := range out {
		trimmed := strings.TrimLeft(line, " ")
		prefix := "$ref: "
		if strings.HasPrefix(trimmed, "- $ref: ") {
			prefix = "- $ref: "
		}
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		raw := strings.TrimPrefix(trimmed, prefix)
		value, quote := raw, ""
		if len(raw) >= 2 && ((raw[0] == '\'' && raw[len(raw)-1] == '\'') || (raw[0] == '"' && raw[len(raw)-1] == '"')) {
			value, quote = raw[1:len(raw)-1], raw[:1]
		}
		normalized, err := normalizedPolicyRef(value)
		if err != nil {
			return nil, err
		}
		if normalized != value {
			out[i] = line[:len(line)-len(trimmed)] + prefix + quote + normalized + quote
		}
	}
	var actual map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(out, "\n")), &actual); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(actual, expected) {
		return nil, fmt.Errorf("YAML policy schema rewrite did not preserve the normalized document")
	}
	return out, nil
}
