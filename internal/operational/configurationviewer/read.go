package configurationviewer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"privacy-proxy/internal/strictjson"
)

type Source struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}
type opened struct {
	base, root         *os.Root
	baseInfo, rootInfo os.FileInfo
	id                 string
	settings           *Settings
}

func (o *opened) close() {
	if o.root != o.base {
		o.root.Close()
	}
	o.base.Close()
}
func regularDirectory(root *os.Root, name string) (*os.Root, os.FileInfo, error) {
	i, e := root.Lstat(name)
	if e != nil || !i.IsDir() {
		return nil, nil, errUnavailable
	}
	r, e := root.OpenRoot(name)
	if e != nil {
		return nil, nil, errUnavailable
	}
	j, e := r.Stat(".")
	if e != nil || !os.SameFile(i, j) {
		r.Close()
		return nil, nil, errUnavailable
	}
	return r, i, nil
}
func openSource(s *Settings, id string) (*opened, error) {
	i, e := os.Lstat(s.Directory)
	if e != nil || !i.IsDir() {
		return nil, errUnavailable
	}
	b, e := os.OpenRoot(s.Directory)
	if e != nil {
		return nil, errUnavailable
	}
	j, e := b.Stat(".")
	if e != nil || !os.SameFile(i, j) {
		b.Close()
		return nil, errUnavailable
	}
	o := &opened{base: b, root: b, baseInfo: i, rootInfo: i, id: id, settings: s}
	if s.Layout == "single" {
		if id != "source" {
			o.close()
			return nil, os.ErrNotExist
		}
	} else {
		r, info, e := regularDirectory(b, id)
		if e != nil {
			o.close()
			return nil, os.ErrNotExist
		}
		o.root = r
		o.rootInfo = info
	}
	return o, nil
}
func (o *opened) live() error {
	i, e := os.Lstat(o.settings.Directory)
	if e != nil || !i.IsDir() || !os.SameFile(i, o.baseInfo) {
		return errUnavailable
	}
	if o.settings.Layout == "folders" {
		j, e := o.base.Lstat(o.id)
		if e != nil || !j.IsDir() || !os.SameFile(j, o.rootInfo) {
			return errUnavailable
		}
	}
	return nil
}
func entries(ctx context.Context, r *os.Root, budget *int) ([]os.DirEntry, error) {
	f, e := r.Open(".")
	if e != nil {
		return nil, errUnavailable
	}
	defer f.Close()
	var out []os.DirEntry
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		rows, e := f.ReadDir(32)
		*budget -= len(rows)
		if *budget < 0 {
			return nil, errUnavailable
		}
		out = append(out, rows...)
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errUnavailable
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}
func listSources(ctx context.Context, s *Settings) ([]Source, error) {
	if s.Layout == "single" {
		o, e := openSource(s, "source")
		if e != nil {
			return nil, e
		}
		defer o.close()
		if e = o.live(); e != nil {
			return nil, e
		}
		return []Source{{"source", "Configuration"}}, nil
	}
	i, e := os.Lstat(s.Directory)
	if e != nil || !i.IsDir() {
		return nil, errUnavailable
	}
	r, e := os.OpenRoot(s.Directory)
	if e != nil {
		return nil, errUnavailable
	}
	defer r.Close()
	j, e := r.Stat(".")
	if e != nil || !os.SameFile(i, j) {
		return nil, errUnavailable
	}
	budget := MaxFiles
	rows, e := entries(ctx, r, &budget)
	if e != nil {
		return nil, e
	}
	out := []Source{}
	for _, row := range rows {
		if !sourceName.MatchString(row.Name()) || !row.IsDir() {
			continue
		}
		if len(out) == MaxCandidates {
			return nil, errUnavailable
		}
		out = append(out, Source{row.Name(), row.Name()})
	}
	j, e = os.Lstat(s.Directory)
	if e != nil || !j.IsDir() || !os.SameFile(i, j) {
		return nil, errUnavailable
	}
	return out, nil
}

type stamp struct {
	path      string
	info      os.FileInfo
	hash      [32]byte
	directory bool
}
type capture struct {
	body       []byte
	tag        string
	stamps     []stamp
	base, root os.FileInfo
}

func sameInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
func (c *capture) unchanged(ctx context.Context, s *Settings, id string, full bool) error {
	o, e := openSource(s, id)
	if e != nil {
		return e
	}
	defer o.close()
	if !os.SameFile(c.base, o.baseInfo) || !sameInfo(c.root, o.rootInfo) {
		return errUnavailable
	}
	for _, v := range c.stamps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		i, e := o.root.Lstat(v.path)
		if e != nil || !sameInfo(i, v.info) || v.directory && !i.IsDir() || !v.directory && !i.Mode().IsRegular() {
			return errUnavailable
		}
		if full && !v.directory {
			raw, _, e := readPathRegular(ctx, o.root, v.path, MaxFileBytes)
			if e != nil || sha256.Sum256(raw) != v.hash {
				return errUnavailable
			}
		}
	}
	return o.live()
}
func readPathRegular(ctx context.Context, r *os.Root, path string, limit int) ([]byte, os.FileInfo, error) {
	parts := strings.Split(path, "/")
	if len(parts) == 1 {
		return readRegular(ctx, r, path, limit)
	}
	if len(parts) != 2 || !sourceName.MatchString(parts[0]) {
		return nil, nil, errUnavailable
	}
	child, _, e := regularDirectory(r, parts[0])
	if e != nil {
		return nil, nil, e
	}
	defer child.Close()
	return readRegular(ctx, child, parts[1], limit)
}
func readRegular(ctx context.Context, r *os.Root, path string, limit int) ([]byte, os.FileInfo, error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	i, e := r.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Size() < 0 || i.Size() > int64(limit) {
		return nil, nil, errUnavailable
	}
	f, e := openRegular(r, path, i)
	if e != nil {
		return nil, nil, errUnavailable
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(raw) > limit || int64(len(raw)) != i.Size() {
		return nil, nil, errUnavailable
	}
	j, e := f.Stat()
	if e != nil || !sameInfo(i, j) {
		return nil, nil, errUnavailable
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	return raw, i, nil
}

func openRegular(r *os.Root, path string, expected os.FileInfo) (*os.File, error) {
	// Nonblocking/no-follow opening closes the Lstat/Open race: replacement by
	// a FIFO must neither block a capture forever nor follow a new symlink.
	// Root.OpenFile itself resolves symlinks, so use openat relative to its
	// confined directory descriptor, with a validated flat basename only.
	if !fileName.MatchString(path) || len(path) > 128 {
		return nil, errUnavailable
	}
	directory, err := r.Open(".")
	if err != nil {
		return nil, errUnavailable
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errUnavailable
	}
	f := os.NewFile(uintptr(fd), path)
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || !sameInfo(expected, i) {
		f.Close()
		return nil, errUnavailable
	}
	return f, nil
}
func sourceObject(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, errUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := strictjson.ReadValue(d, 0, 32)
	if e != nil {
		return nil, errUnavailable
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errUnavailable
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errUnavailable
	}
	return obj, nil
}
func stringField(m map[string]any, key string, max int) bool {
	v, ok := m[key].(string)
	return ok && len(v) > 0 && len(v) <= max
}
func references(d map[string]any) ([]string, string, error) {
	chain, ok := d["chainId"].(string)
	if !ok || len(chain) > 20 || len(chain) == 0 || chain[0] == '0' {
		return nil, "", errUnavailable
	}
	for _, c := range chain {
		if c < '0' || c > '9' {
			return nil, "", errUnavailable
		}
	}
	if d["apiVersion"] != "ops.policy-draft/v1alpha1" || d["kind"] != "PolicyDraft" || !stringField(d, "sourceRevision", 1024) || !stringField(d, "environment", 128) || !stringField(d, "profile", 256) || !stringField(d, "evaluatorVersion", 256) {
		return nil, "", errUnavailable
	}
	orgs, ok := d["organizations"].([]any)
	if !ok || len(orgs) > 256 {
		return nil, "", errUnavailable
	}
	ids := map[string]bool{}
	slugs := map[string]bool{}
	for _, v := range orgs {
		o, ok := v.(map[string]any)
		if !ok {
			return nil, "", errUnavailable
		}
		id, _ := o["id"].(string)
		slug, _ := o["slug"].(string)
		if !orgID.MatchString(id) || ids[id] || slugs[slug] || !stringField(o, "name", 256) || !stringField(o, "slug", 100) {
			return nil, "", errUnavailable
		}
		ids[id] = true
		slugs[slug] = true
	}
	docs, ok := d["documents"].([]any)
	if !ok || len(docs) > 1024 {
		return nil, "", errUnavailable
	}
	paths := []string{"draft.json"}
	seen := map[string]bool{"draft.json": true}
	add := func(v any, kind bool) error {
		o, ok := v.(map[string]any)
		if !ok {
			return errUnavailable
		}
		p, ok := o["path"].(string)
		if !ok || len(p) > 128 || !fileName.MatchString(p) || seen[p] {
			return errUnavailable
		}
		if kind {
			k, _ := o["kind"].(string)
			id, _ := o["organizationId"].(string)
			if !ids[id] || (k != "groups" && k != "contract-registry" && k != "execution-rules") {
				return errUnavailable
			}
		}
		seen[p] = true
		paths = append(paths, p)
		return nil
	}
	for _, v := range docs {
		if add(v, true) != nil {
			return nil, "", errUnavailable
		}
	}
	auth := ""
	for _, key := range []string{"identityCatalog", "runtimeCatalog", "disclosureCatalog", "complianceCatalog", "authCatalog"} {
		if v, ok := d[key]; ok {
			if add(v, false) != nil {
				return nil, "", errUnavailable
			}
			if key == "authCatalog" {
				auth = v.(map[string]any)["path"].(string)
			}
		}
	}
	return paths, auth, nil
}

type selectedRoot struct {
	id    string
	root  *os.Root
	info  os.FileInfo
}

func captureSource(ctx context.Context, s *Settings, id string) (*capture, error) {
	o, e := openSource(s, id)
	if e != nil {
		return nil, e
	}
	defer o.close()
	budget := MaxFiles + MaxRoots
	rows, e := entries(ctx, o.root, &budget)
	if e != nil {
		return nil, e
	}
	inputFiles := 0
	countInputs := func(rows []os.DirEntry) error {
		for _, row := range rows {
			if !row.IsDir() {
				inputFiles++
				if inputFiles > MaxFiles {
					return errUnavailable
				}
			}
		}
		return nil
	}
	if countInputs(rows) != nil {
		return nil, errUnavailable
	}
	flat := false
	var roots []selectedRoot
	for _, v := range rows {
		if v.Name() == "draft.json" {
			flat = true
		}
		if !sourceName.MatchString(v.Name()) || !v.IsDir() {
			continue
		}
		r, info, e := regularDirectory(o.root, v.Name())
		if e != nil {
			return nil, e
		}
		sub, e := entries(ctx, r, &budget)
		if e != nil {
			r.Close()
			return nil, e
		}
		if countInputs(sub) != nil {
			r.Close()
			return nil, errUnavailable
		}
		found := false
		for _, f := range sub {
			if f.Name() == "draft.json" {
				if len(roots) >= MaxRoots {
					r.Close()
					return nil, errUnavailable
				}
				roots = append(roots, selectedRoot{id: v.Name(), root: r, info: info})
				defer r.Close()
				found = true
				break
			}
		}
		if !found {
			r.Close()
		}
	}
	if flat {
		if len(roots) > 0 {
			return nil, errUnavailable
		}
		roots = []selectedRoot{{id: "source", root: o.root, info: o.rootInfo}}
	}
	if len(roots) == 0 || len(roots) > MaxRoots {
		return nil, errUnavailable
	}
	c := &capture{base: o.baseInfo, root: o.rootInfo}
	buf := []byte(`{"apiVersion":"ops.ui-source-package/v1","roots":[`)
	sourceBytes, count := 0, 0
	grow := func(n int) error {
		if n > MaxWireBytes {
			return errUnavailable
		}
		if n > cap(buf) {
			capacity := max(4096, cap(buf)*2, n)
			capacity = min(capacity, MaxWireBytes)
			next := make([]byte, len(buf), capacity)
			copy(next, buf)
			buf = next
		}
		return nil
	}
	appendBytes := func(b []byte) error {
		if grow(len(buf)+len(b)) != nil {
			return errUnavailable
		}
		buf = append(buf, b...)
		return nil
	}
	for n, root := range roots {
		if n > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, `{"id":`...)
		buf = strconv.AppendQuote(buf, root.id)
		buf = append(buf, `,"files":[`...)
		prefix := ""
		if root.root != o.root {
			prefix = root.id + "/"
			c.stamps = append(c.stamps, stamp{path: root.id, info: root.info, directory: true})
		}
		draft, draftInfo, e := readRegular(ctx, root.root, "draft.json", MaxFileBytes)
		if e != nil {
			return nil, e
		}
		obj, e := sourceObject(draft)
		if e != nil {
			return nil, e
		}
		paths, auth, e := references(obj)
		if e != nil {
			return nil, e
		}
		var authRaw []byte
		var authInfo os.FileInfo
		seen := map[string]bool{}
		for _, p := range paths {
			seen[p] = true
		}
		if auth != "" {
			authRaw, authInfo, e = readRegular(ctx, root.root, auth, MaxFileBytes)
			if e != nil {
				return nil, e
			}
			a, e := sourceObject(authRaw)
			if e != nil {
				return nil, e
			}
			if values, exists := a["pinnedDocuments"]; exists {
				pins, ok := values.([]any)
				if !ok || len(pins) > 1024 {
					return nil, errUnavailable
				}
				for _, v := range pins {
					p, ok := v.(map[string]any)
					if !ok {
						return nil, errUnavailable
					}
					name, ok := p["path"].(string)
					if !ok || len(name) > 128 || !fileName.MatchString(name) {
						return nil, errUnavailable
					}
					if !seen[name] {
						paths = append(paths, name)
						seen[name] = true
					}
				}
			}
		}
		sort.Strings(paths)
		for j, path := range paths {
			count++
			if count > MaxFiles {
				return nil, errUnavailable
			}
			var raw []byte
			var info os.FileInfo
			switch path {
			case "draft.json":
				raw, info = draft, draftInfo
			case auth:
				raw, info = authRaw, authInfo
			default:
				raw, info, e = readRegular(ctx, root.root, path, MaxFileBytes)
				if e != nil {
					return nil, e
				}
			}
			sourceBytes += len(raw)
			if sourceBytes > MaxSourceBytes {
				return nil, errUnavailable
			}
			if _, e = sourceObject(raw); e != nil {
				return nil, e
			}
			c.stamps = append(c.stamps, stamp{path: prefix + path, info: info, hash: sha256.Sum256(raw)})
			if j > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, `{"path":`...)
			buf = strconv.AppendQuote(buf, path)
			buf = append(buf, `,"dataBase64":"`...)
			if grow(len(buf)+base64.StdEncoding.EncodedLen(len(raw))+2) != nil {
				return nil, errUnavailable
			}
			buf = base64.StdEncoding.AppendEncode(buf, raw)
			if appendBytes([]byte(`"}`)) != nil {
				return nil, errUnavailable
			}
		}
		if appendBytes([]byte(`]}`)) != nil {
			return nil, errUnavailable
		}
	}
	if appendBytes([]byte(`]}`)) != nil {
		return nil, errUnavailable
	}
	if o.live() != nil {
		return nil, errUnavailable
	}
	c.body = buf
	sum := sha256.Sum256(buf)
	c.tag = `"` + hex.EncodeToString(sum[:]) + `"`
	if c.unchanged(ctx, s, id, true) != nil {
		return nil, errUnavailable
	}
	return c, nil
}
