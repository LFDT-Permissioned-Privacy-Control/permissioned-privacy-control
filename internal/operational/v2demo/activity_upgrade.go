package v2demo

import (
	"context"

	"github.com/google/uuid"
	"privacy-proxy/internal/operational/activitysql"
)

// UpgradeActivity applies only the qualified activity catalog migration, using
// the existing demo's owner connection. The caller must first stop every OPS
// instance sharing this database. It never initializes or reconfigures a source,
// changes its generation, or writes the demo state or local activity buffer.
func UpgradeActivity(ctx context.Context, root string, drained bool) error {
	s, err := activityUpgradeState(root, drained)
	if err != nil {
		return err
	}
	return activitysql.Migrate(ctx, s.dsn("activity", "postgres"), "demo_activity_writer", "demo_activity_reader", "demo_activity_retention", true)
}

func activityUpgradeState(root string, drained bool) (State, error) {
	if !drained {
		return State{}, ErrInvalid
	}
	root, err := canonicalRoot(root)
	if err != nil {
		return State{}, err
	}
	s, err := readState(root)
	if err != nil {
		return State{}, err
	}
	validID := func(value string) bool {
		id, e := uuid.Parse(value)
		return e == nil && id != uuid.Nil && id.String() == value
	}
	if !s.Configured || !validID(s.ActivityGeneration) || !validID(s.Epochs["activitySource"]) || !validID(s.Epochs["activityProducer"]) || s.Secrets["DEMO_POSTGRES_PASSWORD"] == "" || s.Ports.Postgres < 1 || s.Ports.Postgres > 65535 {
		return State{}, ErrInvalid
	}
	return s, nil
}
