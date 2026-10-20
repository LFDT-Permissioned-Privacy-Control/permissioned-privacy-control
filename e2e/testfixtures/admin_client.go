// Package testfixtures provides HTTP-level test helpers for the admin
// REST API. Mirrors the Playwright RBACApiClient surface (helpers/rbac-api.ts)
// so migrated specs read close to the originals.
//
// Use [Fixture] (fixture.go) when you want resource tracking + cleanup
// per test. Use AdminClient directly when you only need one or two raw
// calls and want to manage cleanup yourself.
package testfixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// AdminClient is a typed HTTP client for /api/v1/admin/* endpoints.
// Tests reach the admin REST surface through this client rather than
// the internal rbac.Store interface — the whole point of the
// Playwright→Go migration is to preserve the HTTP-level coverage.
//
// In the test environment ADMIN_API_TOKEN is unset, so the admin
// middleware passes requests through without an X-Admin-Token. If a
// test needs to exercise the authenticated admin path, set AdminToken
// (or use a higher-level helper).
type AdminClient struct {
	BaseURL    string
	HTTPClient *http.Client
	AdminToken string // optional; if non-empty, sent as X-Admin-Token

	// AuthHeader overrides Authorization for a request (e.g. for JWT-admin
	// tests). When set, AdminToken is ignored on that request. Cleared
	// after each call.
	authHeaderOverride string
}

// NewAdminClient returns a client bound to baseURL.
func NewAdminClient(baseURL string) *AdminClient {
	return &AdminClient{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// WithJWT returns a clone of the client that sends the given JWT in
// Authorization for a single request. Used by tests that need to
// verify tier-2 (JWT-admin) permission gates.
func (c *AdminClient) WithJWT(token string) *AdminClient {
	clone := *c
	clone.authHeaderOverride = "Bearer " + token
	clone.AdminToken = "" // JWT path; don't also send admin token
	return &clone
}

// === Types (mirror Playwright rbac-api.ts shapes, current claim model) ===

// Claim values gating admin/upgrade/deploy access. As of RD-853 the
// 'read' and 'write' values were removed; only these three remain.
type Claim string

const (
	ClaimAdmin   Claim = "admin"
	ClaimUpgrade Claim = "upgrade"
	ClaimDeploy  Claim = "deploy"
)

type Organization struct {
	ID        string         `json:"id"`
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	Settings  map[string]any `json:"settings"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

type Group struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	ParentID    string `json:"parent_id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Depth       int    `json:"depth"`
	Path        string `json:"path"`
	IsOrgAdmin  bool   `json:"is_org_admin"`
	AutoCreated bool   `json:"auto_created"`
}

type GroupAccess struct {
	ID             string   `json:"id"`
	GroupID        string   `json:"group_id"`
	AllowedMethods []string `json:"allowed_methods"`
	Claims         []Claim  `json:"claims"`
}

type User struct {
	ID         string         `json:"id"`
	ExternalID string         `json:"external_id"`
	KYC        bool           `json:"kyc"`
	Banned     bool           `json:"banned"`
	Note       string         `json:"note"`
	Metadata   map[string]any `json:"metadata"`
}

type UserMembership struct {
	ID              string  `json:"id"`
	UserID          string  `json:"user_id"`
	GroupID         string  `json:"group_id"`
	Source          string  `json:"source"`
	ZKCredentialRef string  `json:"zk_credential_ref"`
	ExpiresAt       *string `json:"expires_at"`
}

type MembershipWithGroup struct {
	Membership UserMembership `json:"membership"`
	Group      Group          `json:"group"`
}

type Contract struct {
	ID       string         `json:"id"`
	OrgID    string         `json:"org_id"`
	Address  string         `json:"address"`
	Name     string         `json:"name"`
	ABI      string         `json:"abi"`
	Metadata map[string]any `json:"metadata"`
}

type ContractGrant struct {
	ID             string   `json:"id"`
	GroupID        string   `json:"group_id"`
	ContractID     string   `json:"contract_id"`
	AllowedMethods []string `json:"allowed_methods"`
	Claims         []Claim  `json:"claims"`
}

// EffectivePermissions is the response from
// GET /api/v1/admin/users/:user_id/effective-permissions.
type EffectivePermissions struct {
	UserID         string           `json:"user_id"`
	OrgID          string           `json:"org_id"`
	AllowedMethods []string         `json:"allowed_methods"`
	Claims         []Claim          `json:"claims"`
	Groups         []Group          `json:"groups"`
	Memberships    []UserMembership `json:"memberships"`
}

// === Request bodies ===

type CreateOrgInput struct {
	Slug     string         `json:"slug"`
	Name     string         `json:"name"`
	Settings map[string]any `json:"settings,omitempty"`
}

type CreateGroupInput struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ParentID    string `json:"parent_id,omitempty"`
	IsOrgAdmin  bool   `json:"is_org_admin,omitempty"`
}

type GroupAccessInput struct {
	AllowedMethods []string `json:"allowed_methods"`
	Claims         []Claim  `json:"claims"`
	VerboseErrors  bool     `json:"verbose_errors,omitempty"` // RD-1137 Part A
}

type CreateMembershipInput struct {
	GroupID   string  `json:"group_id"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type UpdateUserInput struct {
	KYC    *bool   `json:"kyc,omitempty"`
	Banned *bool   `json:"banned,omitempty"`
	Note   *string `json:"note,omitempty"`
}

type CreateContractInput struct {
	Address      string         `json:"address"`
	Name         string         `json:"name,omitempty"`
	ABI          string         `json:"abi,omitempty"`
	OwnerGroupID string         `json:"owner_group_id,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// FunctionRule mirrors rbac.FunctionRule — a function selector with
// optional ABI parameter constraints. When a grant has function
// rules, only matching selectors pass the contract-access gate.
type FunctionRule struct {
	Selector   string      `json:"selector"`
	ParamRules []ParamRule `json:"param_rules,omitempty"`
}

// ParamRule mirrors rbac.ParamRule. Most tests don't constrain
// params; we only model the fields used so far.
type ParamRule struct {
	Index     int    `json:"index"`
	MustBe    string `json:"must_be,omitempty"`
	MustEqual string `json:"must_equal,omitempty"`
}

type CreateContractGrantInput struct {
	GroupID        string         `json:"group_id"`
	AllowedMethods []string       `json:"allowed_methods,omitempty"`
	Claims         []Claim        `json:"claims,omitempty"`
	Functions      []FunctionRule `json:"functions,omitempty"`
}

// Fns turns N selectors into a slice of FunctionRule with no param
// constraints. Mirrors helpers/rbac-api.ts:fns(...).
func Fns(selectors ...string) []FunctionRule {
	out := make([]FunctionRule, len(selectors))
	for i, s := range selectors {
		out[i] = FunctionRule{Selector: s}
	}
	return out
}

// === Org operations ===

func (c *AdminClient) CreateOrganization(t *testing.T, input CreateOrgInput) Organization {
	t.Helper()
	var out Organization
	c.do(t, http.MethodPost, "/api/v1/admin/orgs", input, &out, http.StatusCreated)
	return out
}

func (c *AdminClient) DeleteOrganization(t *testing.T, orgID string) {
	t.Helper()
	c.do(t, http.MethodDelete, "/api/v1/admin/orgs/"+orgID, nil, nil, http.StatusOK, http.StatusNoContent)
}

func (c *AdminClient) ListOrganizations(t *testing.T) []Organization {
	t.Helper()
	var resp struct {
		Data []Organization `json:"data"`
	}
	c.do(t, http.MethodGet, "/api/v1/admin/orgs", nil, &resp, http.StatusOK)
	return resp.Data
}

// === Group operations ===

func (c *AdminClient) CreateGroup(t *testing.T, orgID string, input CreateGroupInput) Group {
	t.Helper()
	var out Group
	c.do(t, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", input, &out, http.StatusCreated)
	return out
}

func (c *AdminClient) DeleteGroup(t *testing.T, orgID, groupID string) {
	t.Helper()
	c.do(t, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID, nil, nil, http.StatusOK, http.StatusNoContent)
}

func (c *AdminClient) SetGroupAccess(t *testing.T, orgID, groupID string, input GroupAccessInput) GroupAccess {
	t.Helper()
	var out GroupAccess
	c.do(t, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+groupID+"/access", input, &out, http.StatusOK)
	return out
}

// === User + membership operations ===

func (c *AdminClient) ListUsers(t *testing.T) []User {
	t.Helper()
	var resp struct {
		Data []User `json:"data"`
	}
	c.do(t, http.MethodGet, "/api/v1/admin/users", nil, &resp, http.StatusOK)
	return resp.Data
}

// FindUserByExternalID returns nil if no user matches. Walks the
// admin list endpoint — fine for tests where the user list is small.
func (c *AdminClient) FindUserByExternalID(t *testing.T, externalID string) *User {
	t.Helper()
	for _, u := range c.ListUsers(t) {
		if u.ExternalID == externalID {
			user := u
			return &user
		}
	}
	return nil
}

func (c *AdminClient) UpdateUser(t *testing.T, userID string, input UpdateUserInput) User {
	t.Helper()
	var out User
	c.do(t, http.MethodPut, "/api/v1/admin/users/"+userID, input, &out, http.StatusOK)
	return out
}

func (c *AdminClient) CreateMembership(t *testing.T, userID string, input CreateMembershipInput) UserMembership {
	t.Helper()
	var out UserMembership
	c.do(t, http.MethodPost, "/api/v1/admin/users/"+userID+"/memberships", input, &out, http.StatusCreated)
	return out
}

func (c *AdminClient) DeleteMembership(t *testing.T, userID, membershipID string) {
	t.Helper()
	c.do(t, http.MethodDelete, "/api/v1/admin/users/"+userID+"/memberships/"+membershipID, nil, nil, http.StatusOK, http.StatusNoContent)
}

func (c *AdminClient) ListUserMemberships(t *testing.T, userID string) []MembershipWithGroup {
	t.Helper()
	// Handler returns the array directly (admin_rbac_user.go:451),
	// not a {data: [...]} wrapper.
	var out []MembershipWithGroup
	c.do(t, http.MethodGet, "/api/v1/admin/users/"+userID+"/memberships", nil, &out, http.StatusOK)
	return out
}

func (c *AdminClient) GetEffectivePermissions(t *testing.T, userID, orgSlug string) EffectivePermissions {
	t.Helper()
	path := "/api/v1/admin/users/" + userID + "/effective-permissions"
	if orgSlug != "" {
		// Handler reads ?org= (admin_rbac_user.go:756), not ?org_slug=.
		path += "?org=" + orgSlug
	}
	var out EffectivePermissions
	c.do(t, http.MethodGet, path, nil, &out, http.StatusOK)
	return out
}

// === Contract operations ===

func (c *AdminClient) CreateContract(t *testing.T, orgID string, input CreateContractInput) Contract {
	t.Helper()
	var out Contract
	c.do(t, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/contracts", input, &out, http.StatusCreated)
	return out
}

func (c *AdminClient) CreateContractGrant(t *testing.T, orgID, address string, input CreateContractGrantInput) ContractGrant {
	t.Helper()
	var out ContractGrant
	c.do(t, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/contracts/"+address+"/grants", input, &out, http.StatusCreated)
	return out
}

// === Access check ===

// CheckAccessInput mirrors rbac.AccessCheckRequest. Pass one of
// OrgID/OrgSlug; the handler clamps to the caller's scope for
// JWT-admin auth (super-admin via X-Admin-Token sees all).
type CheckAccessInput struct {
	UserExternalID   string  `json:"user_external_id"`
	OrgID            string  `json:"org_id,omitempty"`
	OrgSlug          string  `json:"org_slug,omitempty"`
	Method           string  `json:"method"`
	TargetAddress    string  `json:"target_address,omitempty"`
	FunctionSelector string  `json:"function_selector,omitempty"`
	RequiredClaims   []Claim `json:"required_claims,omitempty"`
}

// CheckAccessResult mirrors rbac.AccessCheckResult (json subset).
type CheckAccessResult struct {
	Allowed      bool   `json:"allowed"`
	AuthRequired bool   `json:"auth_required,omitempty"`
	Reason       string `json:"reason,omitempty"`
	OrgID        string `json:"org_id,omitempty"`
	UserID       string `json:"user_id,omitempty"`
}

func (c *AdminClient) CheckAccess(t *testing.T, input CheckAccessInput) CheckAccessResult {
	t.Helper()
	var out CheckAccessResult
	c.do(t, http.MethodPost, "/api/v1/admin/access/check", input, &out, http.StatusOK)
	return out
}

// === Low-level transport ===

// do is the single HTTP call site for the client. It marshals body,
// sends the request, asserts the response code is one of expectStatus,
// and unmarshals the response into out (if non-nil).
func (c *AdminClient) do(t *testing.T, method, path string, body any, out any, expectStatus ...int) {
	t.Helper()
	url := c.BaseURL + path
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("admin client: marshal %s %s: %v", method, path, err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, reqBody)
	if err != nil {
		t.Fatalf("admin client: build request %s %s: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case c.authHeaderOverride != "":
		req.Header.Set("Authorization", c.authHeaderOverride)
	case c.AdminToken != "":
		req.Header.Set("X-Admin-Token", c.AdminToken)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("admin client: %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	statusOK := false
	for _, want := range expectStatus {
		if resp.StatusCode == want {
			statusOK = true
			break
		}
	}
	if !statusOK {
		t.Fatalf("admin client: %s %s returned %d (want one of %v): %s", method, path, resp.StatusCode, expectStatus, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			t.Fatalf("admin client: unmarshal %s %s response: %v\nbody: %s", method, path, err, string(respBody))
		}
	}
}

// DoRaw is a low-level escape hatch for tests that need to assert on
// HTTP status codes for error paths (e.g. cross-org isolation tests
// that expect 404 or 403). Returns the status code and response body
// without failing the test.
func (c *AdminClient) DoRaw(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	url := c.BaseURL + path
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("admin client DoRaw: marshal: %v", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, url, reqBody)
	req.Header.Set("Content-Type", "application/json")
	switch {
	case c.authHeaderOverride != "":
		req.Header.Set("Authorization", c.authHeaderOverride)
	case c.AdminToken != "":
		req.Header.Set("X-Admin-Token", c.AdminToken)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("admin client DoRaw: %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}
