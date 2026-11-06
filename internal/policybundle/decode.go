package policybundle

import (
	"bytes"
	"encoding/json"
	"io"

	"privacy-proxy/internal/strictjson"
)

func strictValue(raw []byte, maxDepth int) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, maxDepth)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fail(InvalidSchema, "", "", "document", "trailing JSON")
	}
	return value, nil
}

func decodeSource(raw []byte, target any, depth int) error {
	value, err := strictValue(raw, depth)
	if err != nil {
		return err
	}
	return strictjson.ExactDecode(value, target)
}

func decodeDocument(raw []byte, ref DocumentRef, limits Limits) (wireDocument, any, error) {
	var wire wireDocument
	if err := decodeSource(raw, &wire, limits.MaxJSONDepth); err != nil {
		return wire, nil, fail(InvalidSchema, ref.Kind, ref.OrganizationID, ref.Path, err.Error())
	}
	if wire.APIVersion != DocumentAPIVersion || wire.Kind != ref.Kind || wire.OrganizationID != ref.OrganizationID {
		return wire, nil, fail(InvalidSchema, ref.Kind, ref.OrganizationID, ref.Path, "document version/kind/organization does not match manifest")
	}
	var spec any
	switch wire.Kind {
	case Groups:
		spec = &GroupsSpec{}
	case ContractRegistry:
		spec = &RegistrySpec{}
	case ExecutionRules:
		spec = &ExecutionSpec{}
	default:
		return wire, nil, fail(UnsupportedFeature, wire.Kind, wire.OrganizationID, "kind", "unsupported document kind")
	}
	if err := decodeSpec(wire.Spec, spec, limits.MaxJSONDepth); err != nil {
		return wire, nil, fail(InvalidSchema, wire.Kind, wire.OrganizationID, "spec", err.Error())
	}
	return wire, spec, nil
}

func decodeSpec(raw []byte, target any, depth int) error {
	if _, native := target.(*ExecutionSpec); native {
		value, err := strictValue(raw, depth)
		if err != nil {
			return err
		}
		return strictjson.ExactDecodeWithOptions(value, target, strictjson.ShapeOptions{OptionalOmitEmpty: true})
	}
	return decodeSource(raw, target, depth)
}
