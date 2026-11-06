package identity

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"privacy-proxy/internal/strictjson"
)

func jsonValue(raw []byte, depth int) (any, error) {
	if !utf8.Valid(raw) {
		return nil, invalid("json", "document")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, depth)
	if err != nil {
		return nil, invalid("json", "document")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, invalid("trailing", "document")
	}
	return v, nil
}

// Decode rejects ambiguity before constructing typed source and performs no
// network request. Compile checks normalization, trust and group references.
func Decode(raw []byte, limits Limits) (SourceCatalog, error) {
	var source SourceCatalog
	if !limits.Valid() || len(raw) == 0 || len(raw) > limits.MaxIdentityDocumentBytes {
		return source, invalid("limit", "document")
	}
	value, err := jsonValue(raw, limits.MaxCatalogJSONDepth)
	if err != nil {
		return source, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return source, invalid("shape", "document")
	}
	if err := decodedCatalogBounds(object, limits); err != nil {
		return source, err
	}
	profiles, ok := object["profiles"].([]any)
	if !ok || len(profiles) > limits.MaxProfiles {
		return source, invalid("limit", "profiles")
	}
	for _, item := range profiles {
		profile, ok := item.(map[string]any)
		if !ok {
			return source, invalid("shape", "profiles")
		}
		kind, _ := profile["kind"].(string)
		if err := profileFields(profile, kind); err != nil {
			return source, err
		}
	}
	if err := strictjson.ExactDecodeWithOptions(value, &source, strictjson.ShapeOptions{OptionalOmitEmpty: true}); err != nil {
		return SourceCatalog{}, invalid("shape", "document")
	}
	return source, nil
}

func decodedCatalogBounds(object map[string]any, l Limits) error {
	issuers, ok := object["issuers"].([]any)
	if !ok || len(issuers) > l.MaxIssuers {
		return invalid("limit", "issuers")
	}
	keys := 0
	for _, item := range issuers {
		issuer, ok := item.(map[string]any)
		if !ok {
			return invalid("shape", "issuers")
		}
		list, ok := issuer["keys"].([]any)
		if !ok || len(list) > l.MaxKeysPerIssuer || len(list) > l.MaxTotalKeys-keys {
			return invalid("limit", "issuers.keys")
		}
		keys += len(list)
		profiles, ok := issuer["allowedProfiles"].([]any)
		if !ok || len(profiles) > l.MaxProfiles {
			return invalid("limit", "issuers.allowedProfiles")
		}
	}
	mappings, ok := object["mappings"].([]any)
	if !ok || len(mappings) > l.MaxMappings {
		return invalid("limit", "mappings")
	}
	refs := 0
	for _, item := range mappings {
		mapping, ok := item.(map[string]any)
		if !ok {
			return invalid("shape", "mappings")
		}
		list, ok := mapping["groupIds"].([]any)
		if !ok || len(list) > l.MaxGroupsPerMapping || len(list) > l.MaxTotalGroupReferences-refs {
			return invalid("limit", "mappings.groupIds")
		}
		refs += len(list)
	}
	return nil
}

func profileFields(value map[string]any, kind string) error {
	fields := []string{"id", "kind"}
	switch kind {
	case AzureHuman:
		fields = append(fields, "tenantId", "issuer", "apiAudience", "clientId", "delegatedScope", "factSource")
	case AzureService:
		fields = append(fields, "tenantId", "issuer", "apiAudience", "allowedClientIds", "factSource")
	case PrivadoIdentity:
		fields = append(fields, "verifierId", "network", "identityStateContract")
	case PrivadoRole:
		fields = append(fields, "verifierId", "network", "identityStateContract", "allowedCredentialIssuers", "contextDigest", "context", "type", "circuitId", "predicates")
	default:
		return invalid("profile-kind", "profiles.kind")
	}
	if len(value) != len(fields) {
		return invalid("variant-fields", "profiles")
	}
	for _, field := range fields {
		if _, ok := value[field]; !ok {
			return invalid("variant-fields", "profiles")
		}
	}
	return nil
}
