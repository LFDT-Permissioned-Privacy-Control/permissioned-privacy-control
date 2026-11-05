package db

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/configuration"
)

func TestHasActiveExecutionPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, sourceKind, sourceStatus, legacyStatus string
		want                                         bool
	}{
		{name: "empty"},
		{name: "source draft", sourceKind: string(configuration.ExecutionRules), sourceStatus: PolicyStatusDraft},
		{name: "legacy draft", legacyStatus: PolicyStatusDraft},
		{name: "ordinary active source", sourceKind: string(configuration.Groups), sourceStatus: PolicyStatusActive},
		{name: "active source without projection", sourceKind: string(configuration.ExecutionRules), sourceStatus: PolicyStatusActive, want: true},
		{name: "active legacy projection without source", legacyStatus: PolicyStatusActive, want: true},
		{name: "both active", sourceKind: string(configuration.ExecutionRules), sourceStatus: PolicyStatusActive, legacyStatus: PolicyStatusActive, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, org, author, reviewer, artifact := policyActivationFixture(t)
			ctx := t.Context()
			// Create the legacy image first. A generic active source owns its
			// projection, so its real writer guard must remain intact.
			if tc.legacyStatus != "" {
				draft, err := d.CreateExecutionPolicyRevision(ctx, org, 0, "{}", artifact, &author)
				require.NoError(t, err)
				if tc.legacyStatus == PolicyStatusActive {
					_, err = d.ActivateExecutionPolicyRevision(ctx, org, draft.ID, &reviewer)
					require.NoError(t, err)
				}
			}
			if tc.sourceKind != "" {
				// Model an already-existing source independently of its
				// projection, including inconsistent state. Startup inventory
				// must detect either side without interpreting/repairing it.
				_, err := d.Conn().ExecContext(ctx, `INSERT INTO configuration_revisions
 (id,scope_kind,org_id,kind,revision,base_revision,source,digest,dependencies,status,created_by,created_principal_kind,activated_by,activated_at)
 VALUES($1,'organization',$2,$3,1,0,'{}',$4,'{}',$5,$6,'human',
 CASE WHEN $5='active' THEN $7::uuid ELSE NULL END,
 CASE WHEN $5='active' THEN now() ELSE NULL END)`,
					uuid.NewString(), org, tc.sourceKind, "sha256:"+strings.Repeat("a", 64), tc.sourceStatus, author, reviewer)
				require.NoError(t, err)
			}
			active, err := d.HasActiveExecutionPolicy(ctx)
			require.NoError(t, err)
			require.Equal(t, tc.want, active)
			// A failed read must remain an error rather than an empty-store
			// result, even when the successful inventory above was false.
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			_, err = d.HasActiveExecutionPolicy(canceled)
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}
