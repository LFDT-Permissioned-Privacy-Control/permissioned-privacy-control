package testfixtures

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// Fixture is a per-test factory + cleanup tracker for admin REST
// resources. Each Fixture has a stable testID (8 random hex chars) so
// concurrently-running tests don't collide on slugs.
//
// Cleanup is registered via t.Cleanup at construction time; tracked
// resources tear down in reverse-creation order when the test ends.
type Fixture struct {
	t       *testing.T
	Client  *AdminClient
	BaseURL string
	TestID  string

	// Tracked resources for cleanup (reverse-order deletion).
	memberships []struct{ userID, membershipID string }
	contracts   []struct{ orgID, address string }
	groups      []struct{ orgID, groupID string }
	orgs        []string
}

// New constructs a Fixture bound to a running proxy at baseURL.
// Registers t.Cleanup to delete all created resources.
func New(t *testing.T, baseURL string) *Fixture {
	t.Helper()
	f := &Fixture{
		t:       t,
		Client:  NewAdminClient(baseURL),
		BaseURL: baseURL,
		TestID:  randHex(4),
	}
	t.Cleanup(f.cleanup)
	return f
}

// === Unique identifier generation (per-fixture testID) ===

// Slug appends the fixture's testID to base, producing a slug that
// matches the frontend OrganizationForm pattern
// `^[a-z0-9]+(-[a-z0-9]+)*$` and is unique to this test.
func (f *Fixture) Slug(base string) string { return base + "-" + f.TestID }

// DID generates a fresh DID unique to this test.
func (f *Fixture) DID() string {
	return "did:privado:test_" + f.TestID + "_" + randHex(4)
}

// Address generates a fresh 0x-prefixed 20-byte hex address.
func (f *Fixture) Address() string { return "0x" + randHex(20) }

// === Org factories ===

func (f *Fixture) CreateOrg(slugBase string) Organization {
	f.t.Helper()
	org := f.Client.CreateOrganization(f.t, CreateOrgInput{
		Slug: f.Slug(slugBase),
		Name: slugBase + " " + f.TestID,
	})
	f.orgs = append(f.orgs, org.ID)
	return org
}

// === Group factories ===

// CreateGroupOptions controls group creation. Defaults: no parent, not org-admin.
type CreateGroupOptions struct {
	IsOrgAdmin bool
	ParentID   string
}

func (f *Fixture) CreateGroup(orgID, slugBase string, opts CreateGroupOptions) Group {
	f.t.Helper()
	g := f.Client.CreateGroup(f.t, orgID, CreateGroupInput{
		Slug:       f.Slug(slugBase),
		Name:       slugBase + " " + f.TestID,
		IsOrgAdmin: opts.IsOrgAdmin,
		ParentID:   opts.ParentID,
	})
	f.groups = append(f.groups, struct{ orgID, groupID string }{orgID, g.ID})
	return g
}

// SetGroupAccess is a passthrough to the client; included on the
// fixture for ergonomics (the access row is implicitly cleaned up
// when the group is deleted).
func (f *Fixture) SetGroupAccess(orgID, groupID string, input GroupAccessInput) GroupAccess {
	f.t.Helper()
	return f.Client.SetGroupAccess(f.t, orgID, groupID, input)
}

// === User + membership factories ===

// CreateUserOptions controls user creation. KYC defaults to true so
// requests pass the KYC gate; tests that exercise the no-KYC path
// should set KYC=false explicitly.
type CreateUserOptions struct {
	KYC    *bool
	Banned bool
}

// CreateUser provisions a new RBAC user by running the dev-mode
// mock-login flow against the proxy. Returns the user record plus a
// fresh JWT. By default KYC=true; pass KYC: ptr(false) to override.
func (f *Fixture) CreateUser(opts CreateUserOptions) (User, string) {
	f.t.Helper()
	did := f.DID()
	token := f.GetJWTToken(did)
	user := f.Client.FindUserByExternalID(f.t, did)
	if user == nil {
		f.t.Fatalf("CreateUser: user %s not found after JWT mint — did /auth/verify succeed?", did)
	}

	kyc := true
	if opts.KYC != nil {
		kyc = *opts.KYC
	}
	if kyc != user.KYC || opts.Banned != user.Banned {
		updated := f.Client.UpdateUser(f.t, user.ID, UpdateUserInput{
			KYC:    &kyc,
			Banned: &opts.Banned,
		})
		user = &updated
	}
	return *user, token
}

// CreateUserWithMembership extends CreateUser with a membership in
// the given group, then returns the user + JWT. Useful for the common
// "I need a user in this specific group" pattern.
//
// The default DefaultGroupID membership planted by /auth/verify is
// left alone — tests can call DeleteDefaultMembership separately if
// they need to isolate the test group.
func (f *Fixture) CreateUserWithMembership(groupID string, opts CreateUserOptions) (User, string) {
	f.t.Helper()
	user, token := f.CreateUser(opts)
	m := f.Client.CreateMembership(f.t, user.ID, CreateMembershipInput{GroupID: groupID})
	f.memberships = append(f.memberships, struct{ userID, membershipID string }{user.ID, m.ID})
	return user, token
}

// DeleteDefaultMembership removes the user's auto-provisioned
// DefaultGroupID membership. Tests that want isolated group permissions
// (no inherited default) call this after CreateUserWithMembership.
func (f *Fixture) DeleteDefaultMembership(userID string) {
	f.t.Helper()
	const defaultGroupID = "00000000-0000-0000-0000-000000000001"
	for _, m := range f.Client.ListUserMemberships(f.t, userID) {
		if m.Membership.GroupID == defaultGroupID {
			f.Client.DeleteMembership(f.t, userID, m.Membership.ID)
			return
		}
	}
}

// === Contract factories ===

// CreateContractOptions controls contract creation. Address defaults
// to a fresh random 20-byte address; OwnerGroupID is required (no
// implicit default).
type CreateContractOptions struct {
	Address      string
	Name         string
	ABI          string
	OwnerGroupID string
	Metadata     map[string]any
}

func (f *Fixture) CreateContract(orgID string, opts CreateContractOptions) Contract {
	f.t.Helper()
	addr := opts.Address
	if addr == "" {
		addr = f.Address()
	}
	c := f.Client.CreateContract(f.t, orgID, CreateContractInput{
		Address:      addr,
		Name:         opts.Name,
		ABI:          opts.ABI,
		OwnerGroupID: opts.OwnerGroupID,
		Metadata:     opts.Metadata,
	})
	f.contracts = append(f.contracts, struct{ orgID, address string }{orgID, addr})
	return c
}

// === JWT minting ===

// GetJWTToken runs the dev-mode auth flow (/auth/request →
// /auth/verify with a mock JWZ token) and returns an access token
// bound to the given DID. Provisions the user as a side-effect; the
// admin REST API will return it via FindUserByExternalID after.
func (f *Fixture) GetJWTToken(did string) string {
	f.t.Helper()
	return GetJWTToken(f.t, f.BaseURL, did)
}

// GetJWTToken is the package-level form for tests that don't need a
// Fixture (e.g. anonymous tests that mint one token directly).
func GetJWTToken(t *testing.T, baseURL, did string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}

	// Step 1: get a session ID.
	resp, err := client.Post(baseURL+"/auth/request", "application/json", nil)
	if err != nil {
		t.Fatalf("GetJWTToken: auth/request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GetJWTToken: auth/request returned %d: %s", resp.StatusCode, string(body))
	}
	var authReq struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authReq); err != nil {
		t.Fatalf("GetJWTToken: decode session: %v", err)
	}

	// Step 2: verify with the mock JWZ token. The mock verifier
	// extracts the DID from the "mock.<did>" token format.
	verifyBody, _ := json.Marshal(map[string]string{
		"session_id": authReq.SessionID,
		"jwz_token":  "mock." + did,
	})
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, baseURL+"/auth/verify", bytes.NewReader(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("GetJWTToken: auth/verify: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("GetJWTToken: auth/verify returned %d: %s", resp2.StatusCode, string(body))
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("GetJWTToken: decode token: %v", err)
	}
	return tokenResp.AccessToken
}

// === Cleanup ===

// cleanup deletes tracked resources in reverse creation order. Errors
// are logged but do not fail the test — the test's own assertions are
// the source of truth for pass/fail.
func (f *Fixture) cleanup() {
	for i := len(f.memberships) - 1; i >= 0; i-- {
		m := f.memberships[i]
		f.tryDelete("/api/v1/admin/users/" + m.userID + "/memberships/" + m.membershipID)
	}
	for i := len(f.contracts) - 1; i >= 0; i-- {
		c := f.contracts[i]
		f.tryDelete("/api/v1/admin/orgs/" + c.orgID + "/contracts/" + c.address)
	}
	for i := len(f.groups) - 1; i >= 0; i-- {
		g := f.groups[i]
		f.tryDelete("/api/v1/admin/orgs/" + g.orgID + "/groups/" + g.groupID)
	}
	for i := len(f.orgs) - 1; i >= 0; i-- {
		f.tryDelete("/api/v1/admin/orgs/" + f.orgs[i])
	}
}

// tryDelete issues a best-effort DELETE without failing the test on
// 404 / 5xx — by cleanup time the test is already passing or failing
// based on its own assertions.
func (f *Fixture) tryDelete(path string) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, f.BaseURL+path, nil)
	if f.Client.AdminToken != "" {
		req.Header.Set("X-Admin-Token", f.Client.AdminToken)
	}
	resp, err := f.Client.HTTPClient.Do(req)
	if err != nil {
		f.t.Logf("cleanup: DELETE %s: %v", path, err)
		return
	}
	resp.Body.Close()
}

// randHex returns 2n hex characters of crypto-random data.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read errors are vanishingly rare; using time-based
		// fallback keeps tests deterministic if it ever does.
		return fmt.Sprintf("%x", time.Now().UnixNano())[:2*n]
	}
	return hex.EncodeToString(b)
}

// Ptr is a tiny helper for tests that need *bool / *int. Saves
// allocating a variable each time.
func Ptr[T any](v T) *T { return &v }
