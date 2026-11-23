package configurationviewer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/runtimepolicy"
)

func write(t *testing.T, path string, raw []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func draft(paths ...string) []byte {
	docs := []map[string]string{}
	for _, p := range paths {
		docs = append(docs, map[string]string{"kind": "groups", "organizationId": f.Org, "path": p})
	}
	raw, _ := json.Marshal(map[string]any{"apiVersion": "ops.policy-draft/v1alpha1", "kind": "PolicyDraft", "sourceRevision": "candidate", "environment": "test", "chainId": "1", "evaluatorVersion": "native", "profile": "uncompiled", "organizations": []map[string]string{{"id": f.Org, "slug": "bank", "name": "Bank"}}, "documents": docs})
	return raw
}
func source(t *testing.T, dir string) {
	t.Helper()
	write(t, filepath.Join(dir, "draft.json"), draft("groups.json"))
	write(t, filepath.Join(dir, "groups.json"), []byte(`{"number":900719925474099312345,"name":"original"}`))
}
func envelope(t *testing.T, c *capture) map[string]map[string][]byte {
	t.Helper()
	var dto struct {
		APIVersion string `json:"apiVersion"`
		Roots      []struct {
			ID    string `json:"id"`
			Files []struct{ Path, DataBase64 string }
		}
	}
	if e := json.Unmarshal(c.body, &dto); e != nil {
		t.Fatal(e)
	}
	if dto.APIVersion != "ops.ui-source-package/v1" {
		t.Fatal("unexpected source envelope")
	}
	out := map[string]map[string][]byte{}
	for _, r := range dto.Roots {
		out[r.ID] = map[string][]byte{}
		for _, f := range r.Files {
			raw, e := base64.StdEncoding.DecodeString(f.DataBase64)
			if e != nil {
				t.Fatal(e)
			}
			out[r.ID][f.Path] = raw
		}
	}
	return out
}
func TestCaptureFlatNamedSourcesExactBytesAndPublicClosure(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "flat", true: "named"}[named], func(t *testing.T) {
			root := t.TempDir()
			where := root
			if named {
				where = filepath.Join(root, "core")
			}
			source(t, where)
			write(t, filepath.Join(where, ".env"), []byte("PRIVATE_ENV"))
			write(t, filepath.Join(where, "credentials.json"), []byte(`{"secret":"ADJACENT_SECRET"}`))
			if named {
				source(t, filepath.Join(root, "broker"))
			}
			c, e := captureSource(context.Background(), &Settings{Directory: root, Layout: "single"}, "source")
			if e != nil {
				t.Fatal(e)
			}
			out := envelope(t, c)
			id := "source"
			if named {
				id = "core"
				if len(out) != 2 {
					t.Fatal("named roots lost")
				}
			}
			if len(out[id]) != 2 || string(out[id]["groups.json"]) != `{"number":900719925474099312345,"name":"original"}` {
				t.Fatal("bytes changed or adjacent files included")
			}
			if strings.Contains(string(c.body), "ADJACENT_SECRET") || len(c.tag) != 66 {
				t.Fatal("secret or malformed tag")
			}
			if cap(c.body) > MaxWireBytes {
				t.Fatal("unbounded encoded buffer")
			}
		})
	}
}
func TestCaptureRejectsUnsafeMalformedAndMissingInputs(t *testing.T) {
	for _, mode := range []string{"symlink-file", "symlink-root", "symlink-candidate", "symlink-named-root", "traversal", "duplicate-json", "utf8", "missing-reference", "oversized-file", "mixed-flat-named", "artifact-only"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			s := &Settings{Directory: root, Layout: "single"}
			id := "source"
			source(t, root)
			switch mode {
			case "symlink-file":
				other := filepath.Join(t.TempDir(), "groups.json")
				write(t, other, []byte(`{"secret":"SHOULD_NOT_READ"}`))
				if e := os.Remove(filepath.Join(root, "groups.json")); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(other, filepath.Join(root, "groups.json")); e != nil {
					t.Fatal(e)
				}
			case "symlink-root":
				link := filepath.Join(t.TempDir(), "link")
				if e := os.Symlink(root, link); e != nil {
					t.Fatal(e)
				}
				s.Directory = link
			case "symlink-candidate":
				parent := t.TempDir()
				if e := os.Symlink(root, filepath.Join(parent, "candidate")); e != nil {
					t.Fatal(e)
				}
				s.Directory = parent
				s.Layout = "folders"
				id = "candidate"
			case "symlink-named-root":
				parent := t.TempDir()
				if e := os.Symlink(root, filepath.Join(parent, "core")); e != nil {
					t.Fatal(e)
				}
				s.Directory = parent
			case "traversal":
				write(t, filepath.Join(root, "draft.json"), draft("../credentials.json"))
			case "duplicate-json":
				write(t, filepath.Join(root, "groups.json"), []byte(`{"x":1,"x":2}`))
			case "utf8":
				write(t, filepath.Join(root, "groups.json"), []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})
			case "missing-reference":
				if e := os.Remove(filepath.Join(root, "groups.json")); e != nil {
					t.Fatal(e)
				}
			case "oversized-file":
				write(t, filepath.Join(root, "groups.json"), []byte("{}"+strings.Repeat(" ", MaxFileBytes)))
			case "mixed-flat-named":
				source(t, filepath.Join(root, "core"))
			case "artifact-only":
				if e := os.Rename(filepath.Join(root, "draft.json"), filepath.Join(root, "manifest.json")); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := captureSource(context.Background(), s, id); e == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
}
func TestBrokerReadsOnlyExplicitPublicPins(t *testing.T) {
	root := t.TempDir()
	var d map[string]any
	_ = json.Unmarshal(draft(), &d)
	d["authCatalog"] = map[string]string{"path": "auth.json"}
	raw, _ := json.Marshal(d)
	write(t, filepath.Join(root, "draft.json"), raw)
	write(t, filepath.Join(root, "auth.json"), []byte(`{"pinnedDocuments":[{"path":"context.json"}],"key":{"fromEnv":"MUST_NOT_RESOLVE"},"url":"https://never-contact.test"}`))
	write(t, filepath.Join(root, "context.json"), []byte(`{"@context":{}}`))
	write(t, filepath.Join(root, "private.json"), []byte(`{"secret":"PRIVATE"}`))
	c, e := captureSource(context.Background(), &Settings{Directory: root, Layout: "single"}, "source")
	if e != nil {
		t.Fatal(e)
	}
	if len(envelope(t, c)["source"]) != 3 {
		t.Fatal("public pin closure incorrect")
	}
}
func TestFolderUpdatesParentReplacementAndMetadataBackstop(t *testing.T) {
	root := t.TempDir()
	s := &Settings{Directory: root, Layout: "folders"}
	source(t, filepath.Join(root, "candidate"))
	c, e := captureSource(context.Background(), s, "candidate")
	if e != nil {
		t.Fatal(e)
	}
	if e = c.unchanged(context.Background(), s, "candidate", false); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(root, "candidate", "groups.json")
	info, _ := os.Stat(file)
	write(t, file, []byte(`{"number":900719925474099312345,"name":"modified"}`))
	if e = os.Chtimes(file, info.ModTime(), info.ModTime()); e != nil {
		t.Fatal(e)
	}
	if e = c.unchanged(context.Background(), s, "candidate", true); e == nil {
		t.Fatal("full read missed same-size/mtime modification")
	}
	old, e := openSource(s, "candidate")
	if e != nil {
		t.Fatal(e)
	}
	defer old.close()
	if e = os.Rename(filepath.Join(root, "candidate"), filepath.Join(root, "withdrawn")); e != nil {
		t.Fatal(e)
	}
	source(t, filepath.Join(root, "candidate"))
	if old.live() == nil || c.unchanged(context.Background(), s, "candidate", false) == nil {
		t.Fatal("withdrawn descriptor or cached folder resurrected")
	}
	parentOld, e := openSource(s, "candidate")
	if e != nil {
		t.Fatal(e)
	}
	defer parentOld.close()
	moved := root + "-moved"
	if e = os.Rename(root, moved); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(moved)
	source(t, filepath.Join(root, "candidate"))
	if parentOld.live() == nil {
		t.Fatal("parent directory replacement missed")
	}
}
func TestTrustedAudienceFormulaAndSourceNeverChangesAuthority(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	factory, e := runtimepolicy.NewFactory(snapshot, func() time.Time { return time.Unix(f.Now, 0) })
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range []struct {
		name     string
		roles    []string
		audience Audience
		want     bool
	}{
		{"owner-admin", []string{"Admin"}, Audience{OwnerOrganizationIDs: []string{f.Org}}, true},
		{"owner-readonly", []string{"Readonly"}, Audience{OwnerOrganizationIDs: []string{f.Org}}, true},
		{"empty-owner-nonlisted", []string{"Admin"}, Audience{OperatorActorIDs: []string{f.Actor(f.Subject)}}, false},
		{"explicit-operator", []string{"Admin"}, Audience{OperatorActorIDs: []string{f.Actor(f.AdminSubject)}}, true},
		{"explicit-nonadmin", []string{"Auditor"}, Audience{OperatorActorIDs: []string{f.Actor(f.AdminSubject)}}, false},
		{"not-every-owner", []string{"Admin"}, Audience{OwnerOrganizationIDs: []string{f.Org, f.OtherOrg}}, false},
		{"every-owner", []string{"Admin", "Foreign"}, Audience{OwnerOrganizationIDs: []string{f.Org, f.OtherOrg}}, true},
		{"no-source-admin-inference", []string{"Local"}, Audience{OwnerOrganizationIDs: []string{f.Org}}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			v, e := factory.Build(f.Token(t, snapshot, f.AdminSubject, row.roles...))
			if e != nil {
				t.Fatal(e)
			}
			if permits(v, row.audience) != row.want {
				t.Fatal("wrong whole-project audience result")
			}
		})
	}
}

type clientFixture struct {
	h     *Handler
	s     *httptest.Server
	token string
	clock *atomic.Int64
}

func tlsFixture(t *testing.T, settings *Settings) *clientFixture {
	t.Helper()
	snapshot := f.Snapshot(t, nil)
	clock := &atomic.Int64{}
	clock.Store(f.Now)
	h, e := New(Config{Settings: settings, Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(clock.Load(), 0) }})
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return &clientFixture{h, server, f.Token(t, snapshot, f.AdminSubject, "Admin"), clock}
}
func (c *clientFixture) get(t *testing.T, path string, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()
	r, e := http.NewRequest("GET", c.s.URL+path, nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Host = "ops.test"
	r.Header.Set("Authorization", "Bearer "+c.token)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, e := c.s.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(resp.Body)
	if e != nil {
		t.Fatal(e)
	}
	return resp.StatusCode, resp.Header, raw
}
func TestTLSConditionalRefreshAccessExpiryAndRemovedFolder(t *testing.T) {
	root := t.TempDir()
	source(t, filepath.Join(root, "candidate"))
	source(t, filepath.Join(root, "hidden"))
	settings := &Settings{Directory: root, Layout: "folders", Audience: Audience{OwnerOrganizationIDs: []string{f.Org}}, FolderAudiences: map[string]Audience{"hidden": {}}}
	c := tlsFixture(t, settings)
	status, _, raw := c.get(t, Path, nil)
	if status != 200 || strings.Contains(string(raw), "hidden") || !strings.Contains(string(raw), "candidate") {
		t.Fatalf("list access %d %s", status, raw)
	}
	status, _, _ = c.get(t, Path+"/hidden", nil)
	if status != 404 {
		t.Fatal("hidden source oracle")
	}
	status, _, _ = c.get(t, Path+"/unknown", nil)
	if status != 404 {
		t.Fatal("unknown differs from unauthorized")
	}
	status, header, raw := c.get(t, Path+"/candidate", nil)
	if status != 200 || header.Get("ETag") == "" || header.Get("Cache-Control") != "no-store" {
		t.Fatalf("point %d %s", status, raw)
	}
	tag := header.Get("ETag")
	status, _, raw = c.get(t, Path+"/candidate", map[string]string{"If-None-Match": tag})
	if status != 304 || len(raw) != 0 {
		t.Fatal("unchanged capture not conditional")
	}
	write(t, filepath.Join(root, "candidate", "groups.json"), []byte(`{"changed":true}`))
	status, header, _ = c.get(t, Path+"/candidate", map[string]string{"If-None-Match": tag, "Cache-Control": "no-cache"})
	if status != 200 || header.Get("ETag") == tag {
		t.Fatal("explicit refresh or changed source missed")
	}
	tag = header.Get("ETag")
	c.clock.Store(f.Now + 301)
	status, _, raw = c.get(t, Path+"/candidate", map[string]string{"If-None-Match": tag})
	if status != 401 || strings.Contains(string(raw), "roots") {
		t.Fatal("expired evidence returned cache/304")
	}
	c.clock.Store(f.Now)
	if e := os.RemoveAll(filepath.Join(root, "candidate")); e != nil {
		t.Fatal(e)
	}
	status, _, _ = c.get(t, Path+"/candidate", map[string]string{"If-None-Match": tag})
	if status != 404 {
		t.Fatal("removed candidate returned cached source")
	}
	status, _, raw = c.get(t, Path, nil)
	if status != 200 || strings.Contains(string(raw), "candidate") {
		t.Fatal("removed candidate retained in discovery")
	}
	if c.h.used != 0 {
		t.Fatal("removed cache buffer remained charged")
	}
}
func TestTLSClosedIngressAndUnavailableIsNotStartupFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-materialized")
	c := tlsFixture(t, &Settings{Directory: root, Layout: "single", Audience: Audience{OwnerOrganizationIDs: []string{f.Org}}})
	status, _, _ := c.get(t, Path, nil)
	if status != 503 {
		t.Fatal("missing external source must be viewer-only unavailable")
	}
	for _, row := range []struct {
		method, path, host, origin, token, body string
		want                                    int
	}{
		{"POST", Path, "ops.test", "", "", "", 405}, {"HEAD", Path, "ops.test", "", "", "", 405},
		{"GET", Path + "?x=1", "ops.test", "", "", "", 400}, {"GET", Path + "?", "ops.test", "", "", "", 400},
		{"GET", Path, "evil.test", "", "", "", 403}, {"GET", Path, "ops.test", "https://evil.test", "", "", 403},
		{"GET", Path, "ops.test", "", "forged", "", 401}, {"GET", Path, "ops.test", "", "none", "", 401},
		{"GET", Path, "ops.test", "", "", "x", 400},
	} {
		r, e := http.NewRequest(row.method, c.s.URL+row.path, strings.NewReader(row.body))
		if e != nil {
			t.Fatal(e)
		}
		r.Host = row.host
		if row.origin != "" {
			r.Header.Set("Origin", row.origin)
		}
		if row.token != "none" {
			token := row.token
			if token == "" {
				token = c.token
			}
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, e := c.s.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != row.want {
			t.Fatalf("%s %s: %d %s", row.method, row.path, resp.StatusCode, raw)
		}
	}
	disabled := tlsFixture(t, nil)
	status, _, _ = disabled.get(t, Path, nil)
	if status != 503 {
		t.Fatal("absent viewer has unsafe fallback")
	}
}
func TestCaptureAdmissionCoalescingAndReleasedBytes(t *testing.T) {
	root := t.TempDir()
	source(t, root)
	c := tlsFixture(t, &Settings{Directory: root, Layout: "single", Audience: Audience{OwnerOrganizationIDs: []string{f.Org}}})
	ctx := context.Background()
	e, err := c.h.observe(ctx, "source", false)
	if err != nil {
		t.Fatal(err)
	}
	charged := c.h.used
	if charged != cap(e.capture.body) || e.users != 1 {
		t.Fatal("retained encoded bytes unaccounted")
	}
	c.h.mu.Lock()
	c.h.removeLocked("source", e)
	c.h.mu.Unlock()
	if c.h.used != charged {
		t.Fatal("eviction forgot active HTTP reader")
	}
	c.h.release(e)
	if c.h.used != 0 {
		t.Fatal("last HTTP reader did not release bytes")
	}
	c.h.inflight = 2
	if _, err = c.h.observe(ctx, "source", true); !errors.Is(err, errBusy) {
		t.Fatal("distinct captures bypassed global gate")
	}
	c.h.inflight = 0
	c.h.reserved = maxBufferBytes
	if _, err = c.h.observe(ctx, "source", true); !errors.Is(err, errBusy) {
		t.Fatal("capture ignored global buffer reservations")
	}
	c.h.reserved = 0
	done := make(chan struct{})
	c.h.flights["source"] = done
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = c.h.observe(cancelCtx, "source", false); !errors.Is(err, context.Canceled) {
		t.Fatal("coalesced waiter ignored cancellation")
	}
	delete(c.h.flights, "source")
	close(done)
	status, _, _ := c.get(t, Path+"/source", nil)
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	if status != 200 || c.h.inflight != 0 || c.h.reserved != 0 || c.h.used > maxCacheBytes {
		t.Fatal("request leaked capture budget")
	}
}

func TestInflightSameSourceCoalescesAndDistinctSourcesStayBounded(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"a", "b", "c"} {
		source(t, filepath.Join(root, id))
	}
	c := tlsFixture(t, &Settings{Directory: root, Layout: "folders", Audience: Audience{OwnerOrganizationIDs: []string{f.Org}}})
	started := make(chan string, 2)
	release := make(chan struct{})
	var loads atomic.Int32
	c.h.load = func(ctx context.Context, s *Settings, id string) (*capture, error) {
		loads.Add(1)
		started <- id
		select {
		case <-release:
			return captureSource(ctx, s, id)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	type answer struct {
		e   *observation
		err error
	}
	a := make(chan answer, 1)
	b := make(chan answer, 1)
	go func() { v, e := c.h.observe(context.Background(), "a", true); a <- answer{v, e} }()
	<-started
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.h.observe(wait, "a", true); !errors.Is(err, context.DeadlineExceeded) || loads.Load() != 1 {
		t.Fatal("same-source waiter started a duplicate capture or ignored deadline")
	}
	go func() { v, e := c.h.observe(context.Background(), "b", true); b <- answer{v, e} }()
	<-started
	if _, err := c.h.observe(context.Background(), "c", true); !errors.Is(err, errBusy) || loads.Load() != 2 {
		t.Fatal("third distinct source bypassed admission")
	}
	close(release)
	for _, ch := range []chan answer{a, b} {
		result := <-ch
		if result.err != nil {
			t.Fatal(result.err)
		}
		c.h.release(result.e)
	}
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	if c.h.inflight != 0 || c.h.reserved != 0 || len(c.h.flights) != 0 || c.h.used > maxCacheBytes {
		t.Fatal("concurrent captures leaked source budget")
	}
}

func TestExpiryAfterCaptureBlocksPreparedBodyAndConditionalReply(t *testing.T) {
	for _, conditional := range []bool{false, true} {
		t.Run(strconv.FormatBool(conditional), func(t *testing.T) {
			root := t.TempDir()
			source(t, root)
			c := tlsFixture(t, &Settings{Directory: root, Layout: "single", Audience: Audience{OwnerOrganizationIDs: []string{f.Org}}})
			var expire atomic.Bool
			c.h.load = func(ctx context.Context, s *Settings, id string) (*capture, error) {
				cap, e := captureSource(ctx, s, id)
				if expire.Load() {
					c.clock.Store(f.Now + 301)
				}
				return cap, e
			}
			headers := map[string]string{"Cache-Control": "no-cache"}
			if conditional {
				status, h, _ := c.get(t, Path+"/source", nil)
				if status != 200 {
					t.Fatal("warm source")
				}
				headers["If-None-Match"] = h.Get("ETag")
			}
			expire.Store(true)
			status, _, raw := c.get(t, Path+"/source", headers)
			if status != 401 || strings.Contains(string(raw), "roots") {
				t.Fatal("expired post-capture authority published body or 304")
			}
		})
	}
}

func TestSourceAndDiscoveryBudgets(t *testing.T) {
	t.Run("root-count", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < MaxRoots+1; i++ {
			source(t, filepath.Join(root, "root"+strconv.Itoa(i)))
		}
		if _, e := captureSource(context.Background(), &Settings{Directory: root, Layout: "single"}, "source"); e == nil {
			t.Fatal("root ceiling ignored")
		}
	})
	t.Run("candidate-count", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < MaxCandidates+1; i++ {
			if e := os.Mkdir(filepath.Join(root, "candidate"+strconv.Itoa(i)), 0700); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := listSources(context.Background(), &Settings{Directory: root, Layout: "folders"}); e == nil {
			t.Fatal("candidate ceiling ignored")
		}
	})
	t.Run("input-file-count", func(t *testing.T) {
		root := t.TempDir()
		write(t, filepath.Join(root, "draft.json"), draft())
		for i := 0; i < MaxFiles; i++ {
			write(t, filepath.Join(root, "adjacent"+strconv.Itoa(i)+".json"), []byte(`{}`))
		}
		if _, e := captureSource(context.Background(), &Settings{Directory: root, Layout: "single"}, "source"); e == nil {
			t.Fatal("input enumeration ceiling ignored")
		}
	})
	t.Run("aggregate-raw-bytes", func(t *testing.T) {
		root := t.TempDir()
		names := []string{}
		padding := []byte(`{}` + strings.Repeat(" ", MaxFileBytes-2))
		for i := 0; i < 64; i++ {
			name := "document" + strconv.Itoa(i) + ".json"
			names = append(names, name)
			write(t, filepath.Join(root, name), padding)
		}
		write(t, filepath.Join(root, "draft.json"), draft(names...))
		if _, e := captureSource(context.Background(), &Settings{Directory: root, Layout: "single"}, "source"); e == nil {
			t.Fatal("64MiB aggregate source ceiling ignored")
		}
	})
}

func TestTrustedSettingsSyntaxAndDefensiveCopy(t *testing.T) {
	for _, s := range []*Settings{{Directory: "relative", Layout: "single"}, {Directory: "/", Layout: "single"}, {Directory: "/tmp/source", Layout: "infer"}, {Directory: "/tmp/source", Layout: "single", FolderAudiences: map[string]Audience{"child": {}}}, {Directory: "/tmp/source", Layout: "folders", FolderAudiences: map[string]Audience{"../escape": {}}}, {Directory: "/tmp/source", Layout: "single", Audience: Audience{OwnerOrganizationIDs: []string{f.Org, f.Org}}}, {Directory: "/tmp/source", Layout: "single", Audience: Audience{OperatorActorIDs: []string{"admin"}}}} {
		if s.Validate() == nil {
			t.Fatal("invalid deployment settings accepted", s)
		}
	}
	root := t.TempDir()
	source(t, root)
	settings := &Settings{Directory: root, Layout: "single", Audience: Audience{OwnerOrganizationIDs: []string{f.Org}}}
	c := tlsFixture(t, settings)
	settings.Audience.OwnerOrganizationIDs[0] = f.OtherOrg
	status, _, _ := c.get(t, Path+"/source", nil)
	if status != 200 {
		t.Fatal("caller mutated trusted running audience")
	}
	snapshot := f.Snapshot(t, nil)
	if _, e := New(Config{Settings: &Settings{Directory: root, Layout: "single", Audience: Audience{OwnerOrganizationIDs: []string{"ffffffff-ffff-ffff-ffff-ffffffffffff"}}}, Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(f.Now, 0) }}); e == nil {
		t.Fatal("unknown ownership anchor accepted")
	}
}

func TestReplacementBetweenLstatAndOpenRejectsFIFOAndSymlink(t *testing.T) {
	for _, mode := range []string{"fifo", "symlink", "other-inode"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "public.json")
			write(t, path, []byte(`{"public":true}`))
			root, e := os.OpenRoot(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			expected, e := root.Lstat("public.json")
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(path, filepath.Join(dir, "previous.json")); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "fifo":
				if e = syscall.Mkfifo(path, 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e = os.Symlink("previous.json", path); e != nil {
					t.Fatal(e)
				}
			case "other-inode":
				write(t, path, []byte(`{"secret":true}`))
			}
			f, e := openRegular(root, "public.json", expected)
			if f != nil {
				f.Close()
			}
			if e == nil {
				t.Fatal("changed pathname survived the checked nonblocking no-follow open")
			}
		})
	}
}
