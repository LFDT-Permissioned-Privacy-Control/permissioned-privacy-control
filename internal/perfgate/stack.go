package perfgate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

// setupClient serves seeding and control calls: a small keep-alive pool, so
// setup does not leave TIME_WAIT sockets behind for the timed phases.
var setupClient = func() *http.Client {
	c := NewLoadClient(16)
	c.Timeout = 60 * time.Second
	return c
}()

// StackOptions describes one full-server stack: real OPS binary, real
// Postgres (main, audit, tracking), real Redis, mocked node.
type StackOptions struct {
	Name       string
	Binary     string
	Mode       string // "legacy" or "reth"
	Dir        string
	Node       MockNodeConfig
	SeparateDB bool              // tracking DB on its own Postgres instance
	MockProcs  int               // GOMAXPROCS of the mock-node process
	ExtraEnv   map[string]string // overrides, recorded in the report
	Log        func(format string, args ...any)
}

// Stack is a running stack. Close removes everything it started.
type Stack struct {
	Options    StackOptions
	PG         *Postgres
	ExecPG     *Postgres
	Redis      *Container
	Node       *MockProcess
	OPS        *exec.Cmd
	URL        string
	AdminToken string
	Org        string
	Group      string
	Tokens     map[int]string // user -> access token
	Env        map[string]string
	MainDB     *sql.DB // owner connection to the main DB
	AuditDB    *sql.DB
	Admin      *sql.DB // superuser on the main instance (postgres DB)
	ExecAdmin  *sql.DB // superuser on the tracking instance
	mainName   string
	opsLog     *os.File
	opsExited  chan struct{}
}

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}

func (s *Stack) logf(format string, args ...any) {
	if s.Options.Log != nil {
		s.Options.Log(format, args...)
	}
}

// LeftoverContainers lists containers a previous, interrupted run left behind.
func LeftoverContainers(ctx context.Context) ([]string, error) {
	out, err := docker(ctx, "ps", "-a", "-q", "--filter", "label=perfgate=true")
	if err != nil || out == "" {
		return nil, err
	}
	return strings.Fields(out), nil
}

// StartStack provisions containers, the mock node and the OPS process.
func StartStack(ctx context.Context, o StackOptions) (*Stack, error) {
	if leftover, err := LeftoverContainers(ctx); err != nil {
		return nil, err
	} else if len(leftover) > 0 {
		return nil, fmt.Errorf("containers from an interrupted run are still present (label perfgate=true): %v; remove them first", leftover)
	}
	s := &Stack{Options: o, Tokens: map[int]string{}, AdminToken: "perfgate-admin-" + randomHex(16), mainName: "perfgate"}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	var err error
	suffix := randomHex(4)
	if s.PG, err = StartPostgres(ctx, "perfgate-"+o.Name+"-pg-"+suffix); err != nil {
		return nil, err
	}
	s.ExecPG = s.PG
	if o.SeparateDB {
		if s.ExecPG, err = StartPostgres(ctx, "perfgate-"+o.Name+"-exec-"+suffix); err != nil {
			return nil, err
		}
	}
	redisPassword := randomHex(12)
	if s.Redis, err = StartRedis(ctx, "perfgate-"+o.Name+"-redis-"+suffix, redisPassword); err != nil {
		return nil, err
	}
	appPassword := randomHex(12)
	for _, stmt := range []string{
		"CREATE DATABASE " + s.mainName,
		"CREATE DATABASE " + s.mainName + "_audit",
		fmt.Sprintf("CREATE ROLE privacy_proxy_app LOGIN PASSWORD '%s'", appPassword),
		"GRANT CONNECT ON DATABASE " + s.mainName + "_audit TO privacy_proxy_app",
		"CREATE EXTENSION IF NOT EXISTS pg_stat_statements",
	} {
		if _, err := s.PG.Psql(ctx, "postgres", stmt); err != nil {
			return nil, err
		}
	}
	for _, stmt := range []string{"CREATE DATABASE " + s.mainName + "_exec", "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"} {
		if _, err := s.ExecPG.Psql(ctx, "postgres", stmt); err != nil && !strings.Contains(err.Error(), "already exists") {
			return nil, err
		}
	}
	if s.Admin, err = OpenDB(s.PG.DSN("postgres", "postgres", s.PG.Password)); err != nil {
		return nil, err
	}
	if s.ExecAdmin, err = OpenDB(s.ExecPG.DSN("postgres", "postgres", s.ExecPG.Password)); err != nil {
		return nil, err
	}

	if s.Node, err = StartMockProcess(ctx, o.Node, o.Dir, o.MockProcs); err != nil {
		return nil, err
	}
	publicURL, privateURL := s.Node.PublicURL, s.Node.PrivateURL

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	s.URL = "http://127.0.0.1:" + port
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	env := map[string]string{
		"ENVIRONMENT": "development", "GIN_MODE": "release", "PORT": port, "BASE_URL": s.URL, "NODE_URL": publicURL,
		"DATABASE_URL":       s.PG.DSN(s.mainName, "postgres", s.PG.Password),
		"AUDIT_DATABASE_URL": s.PG.DSN(s.mainName+"_audit", "privacy_proxy_app", appPassword),
		// Provisioned for the execution-tracking design (plan §4.11). Today's
		// code does not read it; the runner measures the database either way.
		"EXECUTION_DATABASE_URL": s.ExecPG.DSN(s.mainName+"_exec", "postgres", s.ExecPG.Password),
		"REDIS_URL":              fmt.Sprintf("redis://:%s@127.0.0.1:%s/0", redisPassword, s.Redis.Port),
		"JWT_SECRET":             "perfgate-access-secret-" + randomHex(16), "JWT_REFRESH_SECRET": "perfgate-refresh-secret-" + randomHex(16),
		"ADMIN_API_TOKEN": s.AdminToken, "ALLOW_MOCK_LOGIN": "true", "MOCK_SIGNATURES": "false", "ENABLE_TRAVEL_RULE": "true",
		"VERIFIER_ID": "did:privado:verifier:dev-0000000000000000", "DISABLE_COINGECKO": "true",
		"MAX_CONCURRENT_REQUESTS": "5000", "EXPLORER_DATABASE_URL": "", "DB_MAX_OPEN_CONNS": "30",
		"AUDIT_BUFFER_DIR": filepath.Join(o.Dir, "audit-buffer"),
	}
	if o.Mode == "reth" {
		seed := make([]byte, ed25519.SeedSize)
		copy(seed, crypto.Keccak256([]byte("perfgate-policy-key"), []byte(o.Name)))
		keyFile := filepath.Join(o.Dir, "policy-key")
		if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
			return nil, err
		}
		env["OPS_NODE_POLICY_MODE"] = "reth"
		env["OPS_NODE_POLICY_URL"] = privateURL
		env["OPS_NODE_POLICY_TOKEN"] = o.Node.PrivateToken
		env["OPS_NODE_POLICY_PRIVATE_KEY_FILE"] = keyFile
		env["OPS_NODE_POLICY_KEY_ID"] = "perfgate"
		env["OPS_NODE_POLICY_CHAIN_ID"] = strconv.FormatUint(o.Node.ChainID, 10)
		env["OPS_NODE_POLICY_DEPLOYMENT_ID"] = o.Node.DeploymentID
		env["PLATFORM_ADMIN_SUBJECTS"] = strings.Join(policyReviewers[:], ",")
	}
	for k, v := range o.ExtraEnv {
		env[k] = v
	}
	s.Env = env
	if s.MainDB, err = OpenDB(env["DATABASE_URL"]); err != nil {
		return nil, err
	}
	if s.AuditDB, err = OpenDB(s.PG.DSN(s.mainName+"_audit", "postgres", s.PG.Password)); err != nil {
		return nil, err
	}
	if err := s.startOPS(ctx); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *Stack) startOPS(ctx context.Context) error {
	log, err := os.Create(filepath.Join(s.Options.Dir, "ops.log"))
	if err != nil {
		return err
	}
	s.opsLog = log
	cmd := exec.Command(s.Options.Binary)
	cmd.Dir = s.Options.Dir // no developer .env/config is picked up
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.TempDir(), "LANG=C"}
	for k, v := range s.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.OPS = cmd
	s.opsExited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(s.opsExited) }()
	ready := s.URL + "/health"
	if s.Options.Mode == "reth" {
		ready = s.URL + "/ready"
	}
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.opsExited:
			return fmt.Errorf("OPS exited during startup; see %s", log.Name())
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := setupClient.Get(ready)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("OPS did not become ready at %s; see %s", ready, log.Name())
}

// Close stops OPS, the mock node and removes the containers.
func (s *Stack) Close() {
	if s.OPS != nil && s.OPS.Process != nil {
		_ = syscall.Kill(-s.OPS.Process.Pid, syscall.SIGINT)
		select {
		case <-s.opsExited:
		case <-time.After(20 * time.Second):
			_ = syscall.Kill(-s.OPS.Process.Pid, syscall.SIGKILL)
			<-s.opsExited
		}
	}
	if s.opsLog != nil {
		s.opsLog.Close()
	}
	s.Node.Close()
	for _, db := range []*sql.DB{s.MainDB, s.AuditDB, s.Admin, s.ExecAdmin} {
		if db != nil {
			db.Close()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if s.ExecPG != nil && s.ExecPG != s.PG {
		s.ExecPG.Remove(ctx)
	}
	if s.PG != nil {
		s.PG.Remove(ctx)
	}
	s.Redis.Remove(ctx)
}

// api performs one JSON request against OPS and decodes the reply.
func (s *Stack) api(method, path string, body any, token string, admin bool, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	for attempt := 0; ; attempt++ {
		if seeker, ok := reader.(io.Seeker); ok {
			_, _ = seeker.Seek(0, io.SeekStart)
		}
		req, err := http.NewRequest(method, s.URL+path, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if admin {
			req.Header.Set("X-Admin-Token", token)
		} else if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := setupClient.Do(req)
		if err != nil {
			return err
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// Setup is outside every timed phase; back off from setup rate limits.
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 60 {
			time.Sleep(time.Duration(250*(attempt+1)) * time.Millisecond)
			continue
		}
		if resp.StatusCode >= 300 {
			return fmt.Errorf("%s %s: HTTP %d: %.300s", method, path, resp.StatusCode, data)
		}
		if out != nil && len(data) > 0 {
			return json.Unmarshal(data, out)
		}
		return nil
	}
}

func (s *Stack) adminAPI(method, path string, body, out any) error {
	return s.api(method, "/api/v1/admin"+path, body, s.AdminToken, true, out)
}

func (s *Stack) login(did string) (string, error) {
	var session struct {
		SessionID string `json:"session_id"`
	}
	if err := s.api(http.MethodPost, "/auth/request", map[string]any{}, "", false, &session); err != nil {
		return "", err
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := s.api(http.MethodPost, "/auth/verify", map[string]any{"session_id": session.SessionID, "jwz_token": "mock." + did}, "", false, &token); err != nil {
		return "", err
	}
	if token.AccessToken == "" {
		return "", fmt.Errorf("login returned no token")
	}
	return token.AccessToken, nil
}

// Seed creates one org and group (all methods, deploy claim, as the V1
// Gasstorm fixture), then per user: login, KYC, membership, re-login and wallet
// links via the real challenge/verify flow.
func (s *Stack) Seed(senders []Sender, workers int) error {
	var org, group struct {
		ID string `json:"id"`
	}
	if err := s.adminAPI(http.MethodPost, "/orgs", map[string]any{"slug": "perfgate", "name": "Gate 2 load"}, &org); err != nil {
		return err
	}
	if err := s.adminAPI(http.MethodPost, "/orgs/"+org.ID+"/groups", map[string]any{"slug": "perfgate", "name": "Gate 2 load"}, &group); err != nil {
		return err
	}
	if err := s.adminAPI(http.MethodPut, "/orgs/"+org.ID+"/groups/"+group.ID+"/access", map[string]any{"claims": []string{"deploy"}, "allowed_methods": []string{"*"}}, nil); err != nil {
		return err
	}
	s.Org, s.Group = org.ID, group.ID
	// Configured compliance, identical on both trees: enforced, a threshold far
	// above the 1-wei transfers, a manual native price and a non-empty
	// sanctions list, so every transfer runs the full allow branch (sanctions
	// lookups, valuation, threshold, compliance log row).
	if err := s.adminAPI(http.MethodPut, "/orgs/"+org.ID+"/compliance/config", map[string]any{"enabled": true, "threshold_fiat": 1000.0, "unknown_price_policy": "forbidden", "enforcement_mode": "enforce"}, nil); err != nil {
		return err
	}
	if err := s.adminAPI(http.MethodPut, "/orgs/"+org.ID+"/compliance/tokens/native", map[string]any{"symbol": "ETH", "decimals": 18, "prices": map[string]float64{"usd": 3000}}, nil); err != nil {
		return err
	}
	if err := s.adminAPI(http.MethodPost, "/compliance/sanctions", map[string]any{"org_id": org.ID, "address": "0x000000000000000000000000000000000005a9c7", "reason": "perfgate fixture", "source": "perfgate"}, nil); err != nil {
		return err
	}
	byUser := map[int][]Sender{}
	for _, sender := range senders {
		byUser[sender.User] = append(byUser[sender.User], sender)
	}
	users := make(chan int)
	errs := make(chan error, len(byUser))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range users {
				token, err := s.seedUser(u, byUser[u])
				if err != nil {
					errs <- fmt.Errorf("user %d: %w", u, err)
					continue
				}
				mu.Lock()
				s.Tokens[u] = token
				mu.Unlock()
			}
		}()
	}
	for u := range byUser {
		users <- u
	}
	close(users)
	wg.Wait()
	close(errs)
	return <-errs
}

func (s *Stack) seedUser(u int, wallets []Sender) (string, error) {
	did := fmt.Sprintf("did:test:perfgate-%s-%04d", s.Options.Name, u)
	if _, err := s.login(did); err != nil {
		return "", err
	}
	var users struct {
		Data []struct {
			ID         string `json:"id"`
			ExternalID string `json:"external_id"`
		} `json:"data"`
	}
	if err := s.adminAPI(http.MethodGet, "/users?search="+url.QueryEscape(did), nil, &users); err != nil {
		return "", err
	}
	uid := ""
	for _, candidate := range users.Data {
		if candidate.ExternalID == did {
			uid = candidate.ID
		}
	}
	if uid == "" {
		return "", fmt.Errorf("user %s not found", did)
	}
	if err := s.adminAPI(http.MethodPut, "/users/"+uid, map[string]any{"kyc": true}, nil); err != nil {
		return "", err
	}
	var memberships []struct {
		Membership struct {
			ID string `json:"id"`
		} `json:"membership"`
	}
	if err := s.adminAPI(http.MethodGet, "/users/"+uid+"/memberships", nil, &memberships); err != nil {
		return "", err
	}
	for _, m := range memberships {
		if err := s.adminAPI(http.MethodDelete, "/users/"+uid+"/memberships/"+m.Membership.ID, nil, nil); err != nil {
			return "", err
		}
	}
	if err := s.adminAPI(http.MethodPost, "/users/"+uid+"/memberships", map[string]any{"group_id": s.Group}, nil); err != nil {
		return "", err
	}
	token, err := s.login(did)
	if err != nil {
		return "", err
	}
	for _, wallet := range wallets {
		var challenge struct {
			Message string `json:"message"`
			Nonce   string `json:"nonce"`
		}
		if err := s.api(http.MethodPost, "/api/v1/eth/link/challenge", map[string]any{}, token, false, &challenge); err != nil {
			return "", err
		}
		signature, err := crypto.Sign(accounts.TextHash([]byte(challenge.Message)), wallet.Key)
		if err != nil {
			return "", err
		}
		signature[64] += 27
		if err := s.api(http.MethodPost, "/api/v1/eth/link/verify", map[string]any{"nonce": challenge.Nonce, "address": wallet.Address, "signature": "0x" + hex.EncodeToString(signature)}, token, false, nil); err != nil {
			return "", err
		}
	}
	return token, nil
}

var policyReviewers = [2]string{"did:test:perfgate-policy-author", "did:test:perfgate-policy-reviewer"}

// ActivateExecutionPolicy (Reth mode) imports the org's configuration as its
// baseline execution policy and activates it with two administrators, as the
// V2 acceptance stack does: V2 executes only under an active reviewed policy,
// and the published facts then carry it.
func (s *Stack) ActivateExecutionPolicy() error {
	var group struct {
		ID string `json:"id"`
	}
	if err := s.adminAPI(http.MethodPost, "/orgs/"+s.Org+"/groups", map[string]any{"slug": "reviewers", "name": "Reviewers", "is_org_admin": true}, &group); err != nil {
		return err
	}
	if err := s.adminAPI(http.MethodPut, "/orgs/"+s.Org+"/groups/"+group.ID+"/access", map[string]any{"allowed_methods": []string{"*"}, "claims": []string{}}, nil); err != nil {
		return err
	}
	var tokens []string
	for _, did := range policyReviewers {
		if _, err := s.login(did); err != nil {
			return err
		}
		var onboard struct {
			UserID string `json:"user_id"`
		}
		if err := s.adminAPI(http.MethodPost, "/orgs/"+s.Org+"/memberships/by-did", map[string]any{"did": did, "group_id": group.ID}, &onboard); err != nil {
			return err
		}
		if err := s.adminAPI(http.MethodPut, "/users/"+onboard.UserID, map[string]any{"kyc": true}, nil); err != nil {
			return err
		}
		token, err := s.login(did)
		if err != nil {
			return err
		}
		tokens = append(tokens, token)
	}
	prefix := "/api/v1/admin/orgs/" + s.Org + "/configuration/execution-rules"
	var context struct {
		Source json.RawMessage `json:"source"`
	}
	if err := s.api(http.MethodGet, prefix+"/context", nil, tokens[0], false, &context); err != nil {
		return err
	}
	var candidate struct {
		ID string `json:"id"`
	}
	if err := s.api(http.MethodPost, prefix+"/revisions", context.Source, tokens[0], false, &candidate); err != nil {
		return err
	}
	if err := s.api(http.MethodPost, prefix+"/revisions/"+candidate.ID+"/simulate", map[string]any{"coactivate": []string{}}, tokens[1], false, nil); err != nil {
		return err
	}
	return s.api(http.MethodPost, prefix+"/revisions/"+candidate.ID+"/activate", map[string]any{"coactivate": []string{}}, tokens[1], false, nil)
}

// WaitFactsCurrent blocks until the node has applied the database's current
// fact version (V2 only), so warm-up never starts inside a publication window.
func (s *Stack) WaitFactsCurrent(ctx context.Context, limit time.Duration) (uint64, error) {
	var version uint64
	err := waitFor(ctx, limit, func() bool {
		if s.MainDB.QueryRowContext(ctx, `SELECT version FROM node_policy_clock`).Scan(&version) != nil {
			return false
		}
		stats, err := s.Node.Stats()
		return err == nil && stats.FactsVersion == version
	})
	return version, err
}

// Metrics scrapes the OPS Prometheus endpoint.
func (s *Stack) Metrics() (string, error) {
	resp, err := setupClient.Get(s.URL + "/metrics")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return string(data), err
}
