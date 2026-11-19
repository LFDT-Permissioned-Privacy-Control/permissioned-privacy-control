package v2demo

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestActivityUpgradeRequiresDrainedConfiguredOwnedState(t *testing.T) {
	root := t.TempDir()
	base := State{Version: 1, Root: root, Configured: true, ActivityGeneration: uuid.NewString(), Ports: Ports{Postgres: 5432}}
	base.Epochs = map[string]string{"activitySource": uuid.NewString(), "activityProducer": uuid.NewString()}
	base.Secrets = map[string]string{"DEMO_POSTGRES_PASSWORD": "test-only-owner-secret"}
	for _, tc := range []struct {
		name    string
		drained bool
		change  func(*State)
	}{
		{"missing drain", false, func(*State) {}},
		{"not configured", true, func(s *State) { s.Configured = false }},
		{"missing generation", true, func(s *State) { s.ActivityGeneration = "" }},
		{"invalid generation", true, func(s *State) { s.ActivityGeneration = "not-a-generation" }},
		{"missing source", true, func(s *State) { s.Epochs["activitySource"] = "" }},
		{"missing producer", true, func(s *State) { s.Epochs["activityProducer"] = "" }},
		{"missing owner secret", true, func(s *State) { s.Secrets["DEMO_POSTGRES_PASSWORD"] = "" }},
		{"invalid port", true, func(s *State) { s.Ports.Postgres = 65536 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.Epochs = map[string]string{"activitySource": base.Epochs["activitySource"], "activityProducer": base.Epochs["activityProducer"]}
			s.Secrets = map[string]string{"DEMO_POSTGRES_PASSWORD": base.Secrets["DEMO_POSTGRES_PASSWORD"]}
			tc.change(&s)
			if err := save(s); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(s.file("private/state.json"))
			if err != nil {
				t.Fatal(err)
			}
			// Every invalid prerequisite is rejected before any database connection.
			if err := UpgradeActivity(context.Background(), root, tc.drained); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid upgrade accepted", err)
			}
			after, err := os.ReadFile(s.file("private/state.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed upgrade changed owned state", err)
			}
		})
	}
	if err := save(base); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(base.file("private/state.json"))
	s, err := activityUpgradeState(root, true)
	if err != nil || s.ActivityGeneration != base.ActivityGeneration || s.Epochs["activitySource"] != base.Epochs["activitySource"] || s.Epochs["activityProducer"] != base.Epochs["activityProducer"] {
		t.Fatal("valid retained source identity rejected or changed", err)
	}
	after, _ := os.ReadFile(base.file("private/state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("upgrade prerequisites rewrote state")
	}
}
