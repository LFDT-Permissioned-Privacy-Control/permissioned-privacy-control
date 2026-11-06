package strictjson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// ShapeOptions is opt-in. Existing source formats keep requiring explicit
// optional:"true" tags; the new bundle's embedded native model also uses its
// existing JSON omitempty tags to identify optional fields.
type ShapeOptions struct{ OptionalOmitEmpty bool }

func ExactDecode(value any, target any) error {
	return ExactDecodeWithOptions(value, target, ShapeOptions{})
}

func ExactDecodeWithOptions(value any, target any, options ShapeOptions) error {
	if err := exactShape(value, reflect.TypeOf(target).Elem(), "document", options); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("document field cannot be serialized")
	}
	if err := json.Unmarshal(b, target); err != nil {
		return fmt.Errorf("document field has an invalid type")
	}
	return nil
}

func ExactShape(value any, typ reflect.Type, path string) error {
	return exactShape(value, typ, path, ShapeOptions{})
}

func exactShape(value any, typ reflect.Type, path string, options ShapeOptions) error {
	if value == nil {
		return fmt.Errorf("%s must not be null", path)
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", path)
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field
			optional := field.Tag.Get("optional") == "true"
			if options.OptionalOmitEmpty {
				for _, tag := range strings.Split(field.Tag.Get("json"), ",")[1:] {
					optional = optional || tag == "omitempty"
				}
			}
			if _, found := object[name]; !found && !optional {
				return fmt.Errorf("%s.%s is required", path, name)
			}
		}
		for key, child := range object {
			field, found := fields[key]
			if !found {
				return fmt.Errorf("%s.%s is not a supported field", path, key)
			}
			if err := exactShape(child, field.Type, path+"."+key, options); err != nil {
				return err
			}
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s must be an explicit array", path)
		}
		for i, item := range items {
			if err := exactShape(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i), options); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", path)
		}
		for key, child := range object {
			if err := exactShape(child, typ.Elem(), path+"."+key, options); err != nil {
				return err
			}
		}
	}
	return nil
}
