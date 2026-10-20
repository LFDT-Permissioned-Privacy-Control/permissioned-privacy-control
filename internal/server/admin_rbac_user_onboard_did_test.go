package server

import (
	"net/http"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DID-validation tests for the by-did onboarding endpoint (RD-1098).
//
// Before the fix the `did` field was accepted verbatim and a not-yet-seen
// value was provisioned into a `users` row. A typo'd DID, the wallet *app* DID
// (vs the user's *account* DID), or arbitrary garbage all returned 201 and
// created a dead membership row that no real login would ever match.

// A real, checksum-valid Privado-main DID (decoded with go-iden3-core/v2:
// method=iden3, blockchain=privado, network=main, checksum OK).
const validIden3DID = "did:iden3:privado:main:2SiJJTxakwEi9fUNDtut3Ezxc1UA1AZLTAyekfgQrW"

func TestValidateOnboardDID(t *testing.T) {
	cases := []struct {
		name         string
		did          string
		allowRelaxed bool // !IsProduction() at the call site
		wantErr      bool
	}{
		{"valid iden3 privado main", validIden3DID, true, false},
		// Last base58 char flipped W->X: parses as a DID but fails the iden3
		// identifier checksum. Rejected regardless of relaxation.
		{"iden3 bad checksum", "did:iden3:privado:main:2SiJJTxakwEi9fUNDtut3Ezxc1UA1AZLTAyekfgQrX", true, true},
		// Well-formed iden3 method but a short/garbage identifier.
		{"iden3 truncated identifier", "did:iden3:privado:main:2SaubQ6Vu4Xdq8eDDfBcZj", true, true},
		{"empty", "", true, true},
		{"plain string", "not-a-did", true, true},
		{"ethereum address", "0x1234567890abcdef1234567890abcdef12345678", true, true},
		{"email", "user@example.com", true, true},
		// Azure AD subjects use the `azuread:` scheme, not a W3C DID.
		{"azuread subject", "azuread:abc-123-def", true, true},
		// Non-iden3 DID methods that parse cleanly are accepted on structure
		// alone (no iden3 checksum to verify). did:test is used by sibling tests.
		{"non-iden3 did:test", "did:test:bob-1234", true, false},

		// RD-1187: the dev/mock login path provisions did:privado:demo_* /
		// mock_* — the underscore breaks the W3C idchar grammar so ParseDID
		// fails. Accept it in non-production (relaxed), reject in production.
		{"dev privado underscore, relaxed (non-prod)", "did:privado:demo_1783498869499", true, false},
		{"dev privado underscore, strict (prod)", "did:privado:demo_1783498869499", false, true},
		// The relaxation must NEVER apply to iden3/polygonid — a malformed
		// iden3-method DID must not bypass the checksum (no dead row, RD-1098).
		{"iden3 method + underscore stays rejected even relaxed", "did:iden3:privado:main:2SiJ_notbase58", true, true},
		{"polygonid method + underscore stays rejected even relaxed", "did:polygonid:polygon:amoy:2q_bad", true, true},
		// Bounded id charset in the fallback: an id that FAILS the strict parse
		// (space) and carries a char outside the relaxed set stays rejected.
		{"relaxed rejects space in id", "did:privado:demo id", true, true},
		{"relaxed rejects underscore id with space", "did:privado:demo_x y", true, true},
		{"relaxed rejects empty id", "did:privado:", true, true},
		{"relaxed rejects uppercase method", "did:Privado:demo_1", true, true},
		// (did:privado:demo#frag / demo/x parse as valid DID-URLs via ParseDID —
		// accepted pre-RD-1187, unchanged here; not exercised by the fallback.)

		// A trailing / doubled / leading colon leaves an EMPTY id segment — must
		// be rejected even when relaxed, or a dead row like "did:privado:demo_:"
		// would be provisioned.
		{"relaxed rejects trailing colon", "did:privado:demo_:", true, true},
		{"relaxed rejects doubled colon", "did:test::", true, true},
		{"relaxed rejects leading colon in id", "did:privado::demo", true, true},
		// Multi-segment ids stay valid — each ':'-separated segment is non-empty.
		{"relaxed accepts multi-segment id", "did:foo:aa:bb:cc", true, false},
		// Length bound: external_id is VARCHAR(255). Enforced before ParseDID, so
		// it applies to both the relaxed and the strict path.
		{"over-255 DID rejected (relaxed)", "did:privado:" + strings.Repeat("a", 260), true, true},
		{"over-255 DID rejected (strict)", "did:privado:" + strings.Repeat("a", 260), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOnboardDID(tc.did, tc.allowRelaxed)
			if tc.wantErr {
				assert.Error(t, err, "expected %q (relaxed=%v) to be rejected", tc.did, tc.allowRelaxed)
			} else {
				assert.NoError(t, err, "expected %q (relaxed=%v) to be accepted", tc.did, tc.allowRelaxed)
			}
		})
	}
}

func TestOnboardByDID_InvalidDID_400_NoDeadRow(t *testing.T) {
	// An invalid DID must be rejected with an opaque 400 and must NOT create a
	// users row (fail-closed — no silent dead membership).
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-inv", Name: "Team", Path: "team-inv"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	bad := []struct{ name, did string }{
		{"bad_checksum", "did:iden3:privado:main:2SiJJTxakwEi9fUNDtut3Ezxc1UA1AZLTAyekfgQrX"},
		{"garbage", "the-app-did-i-copied-by-mistake"},
		{"eth_address", "0x1234567890abcdef1234567890abcdef12345678"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: tc.did, GroupID: normalGroup.ID})
			require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), "invalid did")
			// Opaque: no raw parser internals leaked to the client.
			assert.NotContains(t, w.Body.String(), "checksum")
			assert.NotContains(t, w.Body.String(), "w3c")

			u, err := srv.db.GetUserByExternalID(ctx, tc.did)
			require.NoError(t, err)
			assert.Nil(t, u, "invalid DID must not create a users row")
		})
	}
}

func TestOnboardByDID_ValidIden3DID_201(t *testing.T) {
	// A real checksum-valid Privado DID onboards normally.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-valid", Name: "Team", Path: "team-valid"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: validIden3DID, GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "valid iden3 DID must onboard; body: %s", w.Body.String())

	u, err := srv.db.GetUserByExternalID(ctx, validIden3DID)
	require.NoError(t, err)
	require.NotNil(t, u, "valid DID should have created the users row")
}

func TestOnboardByDID_DevProvisionedDID_201_RD1187(t *testing.T) {
	// RD-1187: a did:privado:demo_* DID (produced by the dev/mock login path;
	// the underscore fails the strict W3C parse) must onboard in non-production.
	// setupTieredAdminTestServer runs a non-production server, so the relaxation
	// applies. Regression for the acceptance-stack "invalid did" 400.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()
	require.False(t, srv.config.IsProduction(), "test server must be non-production for the RD-1187 relaxation")

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-dev", Name: "Team", Path: "team-dev"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	devDID := "did:privado:demo_1783498869499"
	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: devDID, GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "dev-provisioned DID must onboard in non-prod; body: %s", w.Body.String())

	u, err := srv.db.GetUserByExternalID(ctx, devDID)
	require.NoError(t, err)
	require.NotNil(t, u, "dev DID should have created the users row")
}

func TestOnboardByDID_WhitespaceTrimmed(t *testing.T) {
	// A copy-pasted DID with surrounding whitespace must be trimmed and stored
	// in canonical form, so the row matches the DID the user later presents at
	// login (the verified ZK-proof `From`, which carries no whitespace).
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-trim", Name: "Team", Path: "team-trim"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: "  " + validIden3DID + "\n", GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "padded DID should be trimmed and accepted; body: %s", w.Body.String())

	u, err := srv.db.GetUserByExternalID(ctx, validIden3DID)
	require.NoError(t, err)
	require.NotNil(t, u, "DID must be stored trimmed so it matches the login DID")
}
