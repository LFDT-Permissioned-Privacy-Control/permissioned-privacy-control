package activitysql

import (
	"encoding/json"
	"testing"
)

func TestOnlyExactOptionalOrgIndexLifecycleIsQualified(t *testing.T) {
	decode := func() map[string]any {
		var v map[string]any
		if err := json.Unmarshal(expectedCatalog, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	find := func(v map[string]any) map[string]any {
		for _, item := range v["indexes"].([]any) {
			if row := item.(map[string]any); row["name"] == "activity_org_page" {
				return row
			}
		}
		t.Fatal("qualified index absent")
		return nil
	}
	for _, state := range [][2]bool{{false, false}, {false, true}, {true, true}} {
		v, want := decode(), decode()
		row := find(v)
		row["valid"], row["ready"] = state[0], state[1]
		if !stripQualifiedOrgIndex(v, want) {
			t.Fatal("normal lifecycle rejected", state)
		}
	}
	v, want := decode(), decode()
	var keep []any
	for _, item := range v["indexes"].([]any) {
		if item.(map[string]any)["name"] != "activity_org_page" {
			keep = append(keep, item)
		}
	}
	v["indexes"] = keep
	if !stripQualifiedOrgIndex(v, want) {
		t.Fatal("absent optional index rejected")
	}
	for _, mutate := range []func(map[string]any){
		func(r map[string]any) { r["valid"] = true; r["ready"] = false },
		func(r map[string]any) { r["valid"] = nil },
		func(r map[string]any) { r["ready"] = "false" },
		func(r map[string]any) { r["unique_index"] = true },
		func(r map[string]any) { r["primary_index"] = true },
		func(r map[string]any) { r["schema_name"] = "unqualified" },
		func(r map[string]any) { r["relation"] = "runs" },
		func(r map[string]any) { r["predicate"] = "activity_kind = 2" },
		func(r map[string]any) { r["definition"] = "CREATE INDEX activity_org_page ON public.access_logs (id)" },
		func(r map[string]any) { r["extra"] = true },
	} {
		v, want := decode(), decode()
		mutate(find(v))
		if stripQualifiedOrgIndex(v, want) {
			t.Fatal("unqualified optional index accepted")
		}
	}
	v, want = decode(), decode()
	v["indexes"] = append(v["indexes"].([]any), find(v))
	if stripQualifiedOrgIndex(v, want) {
		t.Fatal("duplicate qualified name accepted")
	}
}
