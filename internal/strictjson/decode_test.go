package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

func value(t *testing.T, raw string, depth int) (any, error) {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	return ReadValue(d, 0, depth)
}

func TestStrictSourceRejectsAmbiguousShapes(t *testing.T) {
	type nested struct {
		Name     string  `json:"name"`
		Optional *string `json:"optional,omitempty" optional:"true"`
	}
	type document struct {
		Items []nested `json:"items"`
	}
	for _, raw := range []string{`{"items":[{"name":"a","name":"b"}]}`, `{"items":[{"Name":"a"}]}`, `{"items":[{"name":"a","optional":null}]}`, `{"items":null}`, `{"items":[{}]}`, `{"items":[{"name":"a","unknown":1}]}`} {
		v, err := value(t, raw, 64)
		if err == nil {
			err = ExactDecode(v, &document{})
		}
		if err == nil {
			t.Fatalf("accepted ambiguous source %s", raw)
		}
	}
	v, err := value(t, `{"items":[{"name":"a"}]}`, 64)
	if err != nil {
		t.Fatal(err)
	}
	var got document
	if err := ExactDecode(v, &got); err != nil || got.Items[0].Optional != nil {
		t.Fatal(err)
	}
	if _, err := value(t, `[[[0]]]`, 2); err == nil {
		t.Fatal("depth budget ignored")
	}
	if _, err := value(t, `{"x":`, 64); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}

func TestNativeOptionalShapeIsExplicitlyOptIn(t *testing.T) {
	type native struct {
		Required []string `json:"required"`
		Bound    *int     `json:"bound,omitempty"`
	}
	v, err := value(t, `{"required":[]}`, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExactDecode(v, &native{}); err == nil || err.Error() != "document.bound is required" {
		t.Fatal("legacy required-field convention changed", err)
	}
	if err := ExactDecodeWithOptions(v, &native{}, ShapeOptions{OptionalOmitEmpty: true}); err != nil {
		t.Fatal(err)
	}
	v, err = value(t, `{"required":[],"bound":null}`, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExactDecodeWithOptions(v, &native{}, ShapeOptions{OptionalOmitEmpty: true}); err == nil {
		t.Fatal("opt-in allowed explicit null")
	}
	v, err = value(t, `{"n":9007199254740993}`, 64)
	if err != nil {
		t.Fatal(err)
	}
	if v.(map[string]any)["n"].(json.Number).String() != "9007199254740993" {
		t.Fatal("number rounded")
	}
}
