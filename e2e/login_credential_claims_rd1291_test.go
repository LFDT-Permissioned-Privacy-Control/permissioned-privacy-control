package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/require"
)

// RD-1291: a wallet's login response can carry proof entries the login
// request never asked for. The ZK verifier checks only the entries the
// request asks for, and a plain login asks for none, so the credential data
// in such an entry is unverified wallet input. Before the fix, login added
// the user to every "org:group" named in its rbac_groups field, an org-admin
// group included, and relabelled an existing membership in such a group as
// ZK-attested.
//
// This drives the production-wired server through the wallet callback with
// such a response and checks that login neither adds nor rewrites a
// membership. On the code before the fix, with the stub returning that
// credential data as the old verifier did, both cases fail.
func TestE2E_WalletLogin_CredentialClaimsGrantNoMembership(t *testing.T) {
	srv, serverURL, cleanup := setupE2EWithVerifier(t, &walletResponseVerifier{})
	defer cleanup()

	ctx := t.Context()
	store := srv.DB()

	// A deployment has the default group, which every new user joins; seed it
	// so the new-user case sees the one membership login does add.
	_ = store.CreateOrganization(ctx, &rbac.Organization{ID: rbac.DefaultOrgID, Slug: "default", Name: "Default Organization", Settings: map[string]any{}})
	_ = store.CreateGroup(ctx, &rbac.Group{ID: rbac.DefaultGroupID, OrgID: rbac.DefaultOrgID, Slug: "default", Name: "Default Group", Path: "default"})

	org := &rbac.Organization{ID: uuid.NewString(), Slug: "rd1291", Name: "RD-1291", Settings: map[string]any{}}
	require.NoError(t, store.CreateOrganization(ctx, org))
	admins := &rbac.Group{ID: uuid.NewString(), OrgID: org.ID, Slug: "admins", Name: "Org Admins", Path: "admins", IsOrgAdmin: true}
	require.NoError(t, store.CreateGroup(ctx, admins))
	members := &rbac.Group{ID: uuid.NewString(), OrgID: org.ID, Slug: "members", Name: "Members", Path: "members"}
	require.NoError(t, store.CreateGroup(ctx, members))

	claimed := []string{org.Slug + ":" + admins.Slug, org.Slug + ":" + members.Slug}

	t.Run("a new user joins no claimed group", func(t *testing.T) {
		const did = "did:privado:rd1291_new_user"

		loginWithWalletResponse(t, serverURL, did, claimed)

		user, err := store.GetUserByExternalID(ctx, did)
		require.NoError(t, err)
		require.NotNil(t, user, "login must still create the user")
		for _, g := range []*rbac.Group{admins, members} {
			m, err := store.GetMembershipByUserAndGroup(ctx, user.ID, g.ID)
			require.NoError(t, err)
			require.Nil(t, m, "login added the user to the claimed group %q", g.Slug)
		}
		memberships, err := store.ListUserMemberships(ctx, user.ID)
		require.NoError(t, err)
		require.Len(t, memberships, 1, "login adds only the default group")
		require.Equal(t, rbac.DefaultGroupID, memberships[0].GroupID)
	})

	t.Run("an existing membership keeps its source", func(t *testing.T) {
		const did = "did:privado:rd1291_member"

		user := &rbac.User{ID: uuid.NewString(), ExternalID: did, Metadata: map[string]any{}}
		require.NoError(t, store.CreateUser(ctx, user))
		require.NoError(t, store.CreateMembership(ctx, &rbac.UserMembership{
			ID: uuid.NewString(), UserID: user.ID, GroupID: members.ID, Source: rbac.MembershipSourceAdmin,
		}))

		loginWithWalletResponse(t, serverURL, did, claimed)

		kept, err := store.GetMembershipByUserAndGroup(ctx, user.ID, members.ID)
		require.NoError(t, err)
		require.NotNil(t, kept)
		require.Equal(t, rbac.MembershipSourceAdmin, kept.Source)

		admin, err := store.GetMembershipByUserAndGroup(ctx, user.ID, admins.ID)
		require.NoError(t, err)
		require.Nil(t, admin, "login made the user an org admin")
	})
}

// walletResponseVerifier stands in for the iden3 library on a plain login
// request. The library checks the auth proof, which a test cannot produce,
// and every proof the request asked for (none here), then returns the
// sender's DID. Entries the request did not ask for are left unchecked.
type walletResponseVerifier struct{ mockPrivadoVerifier }

func (v *walletResponseVerifier) VerifyJWZ(_ context.Context, jwzToken string, _ *protocol.AuthorizationRequestMessage, _ string) (string, error) {
	msg, err := decodeWalletResponse(jwzToken)
	if err != nil {
		return "", err
	}
	return msg.From, nil
}

// walletResponseToken builds a JWZ-shaped token whose authorization response
// carries, beside the login, a proof entry nobody asked for, with credential
// data naming groups in rbac_groups. The proof segment is a placeholder.
func walletResponseToken(t *testing.T, did string, groups []string) string {
	t.Helper()

	vp, err := json.Marshal(map[string]any{
		"@type": "VerifiablePresentation",
		"credentialSubject": map[string]any{
			"@type":       "RBACMembership",
			"rbac_groups": groups,
		},
	})
	require.NoError(t, err)

	payload, err := json.Marshal(protocol.AuthorizationResponseMessage{
		ID:       uuid.NewString(),
		Typ:      "application/iden3-zkp-json",
		Type:     protocol.AuthorizationResponseMessageType,
		ThreadID: "mock-thread-id",
		From:     did,
		To:       "did:privado:verifier:test",
		Body: protocol.AuthorizationMessageResponseBody{
			Scope: []protocol.ZeroKnowledgeProofResponse{{
				ID:                     7,
				CircuitID:              "credentialAtomicQueryMTPV2",
				VerifiablePresentation: vp,
			}},
		},
	})
	require.NoError(t, err)

	header := `{"alg":"groth16","circuitId":"authV2","crit":["circuitId"],"typ":"application/iden3-zkp-json"}`
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc(payload) + "." + enc([]byte("{}"))
}

func decodeWalletResponse(jwzToken string) (*protocol.AuthorizationResponseMessage, error) {
	parts := strings.Split(jwzToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWZ token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var msg protocol.AuthorizationResponseMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	if msg.From == "" {
		return nil, fmt.Errorf("no sender DID")
	}
	return &msg, nil
}

// loginWithWalletResponse opens a login session and posts the wallet's
// response to the callback, as a wallet does.
func loginWithWalletResponse(t *testing.T, serverURL, did string, groups []string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Post(serverURL+"/auth/request", "application/json", nil)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "auth request: %s", body)
	var session struct {
		SessionID string `json:"session_id"`
	}
	require.NoError(t, json.Unmarshal(body, &session))

	token := walletResponseToken(t, did, groups)
	resp, err = client.Post(serverURL+"/auth/callback?session="+session.SessionID, "text/plain", bytes.NewReader([]byte(token)))
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "wallet callback: %s", body)
}
