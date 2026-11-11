// Package ssopolicy compiles exact immutable first-party client configuration.
// A Client configures a handoff; it is neither a principal nor a scoped token.
package ssopolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const APIVersion = "ops.sso.clients/v1"
const Kind = "SSOClients"
const GroupEligibility = "any-listed-group"
const ProfileEligibility = "any-human-in-allowed-profiles"

var ErrInvalid = errors.New("invalid SSO client configuration")

type SecretRef struct {
	FromEnv string `json:"fromEnv"`
}
type GroupRef struct {
	OrganizationID string `json:"organizationId"`
	GroupID        string `json:"groupId"`
}
type ClientSource struct {
	ID                     string     `json:"id"`
	DisplayName            string     `json:"displayName"`
	Authentication         string     `json:"authentication"`
	Secret                 SecretRef  `json:"secret"`
	TrustMode              string     `json:"trustMode"`
	TrustedOrganizationIDs []string   `json:"trustedOrganizationIds"`
	EligibleGroups         []GroupRef `json:"eligibleGroups"`
	Eligibility            string     `json:"eligibility"`
	AllowedProfiles        []string   `json:"allowedProfiles"`
	RedirectURIs           []string   `json:"redirectUris"`
}
type Source struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Clients    []ClientSource `json:"clients"`
}
type References interface {
	Organization(string) bool
	Group(string, string) bool
}
type Client struct{ source ClientSource }
type Catalog struct {
	clients                []Client
	index                  map[string]int
	digest, identityDigest string
}

func (c *Catalog) Digest() string         { return c.digest }
func (c *Catalog) IdentityDigest() string { return c.identityDigest }
func (c *Catalog) Client(id string) (Client, bool) {
	i, ok := c.index[id]
	if !ok {
		return Client{}, false
	}
	return Client{clone(c.clients[i].source)}, true
}
func (c *Catalog) Clients() []Client {
	r := make([]Client, len(c.clients))
	for i, v := range c.clients {
		r[i] = Client{clone(v.source)}
	}
	return r
}
func (c Client) Source() ClientSource { return clone(c.source) }
func clone(c ClientSource) ClientSource {
	c.TrustedOrganizationIDs = slices.Clone(c.TrustedOrganizationIDs)
	c.EligibleGroups = slices.Clone(c.EligibleGroups)
	c.AllowedProfiles = slices.Clone(c.AllowedProfiles)
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	return c
}

var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var env = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func uuid(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return e == nil && len(b) == 16 && s == strings.ToLower(s) && !bytes.Equal(b, make([]byte, 16))
}
func sorted(ss []string) bool {
	for i, s := range ss {
		if s == "" || i > 0 && ss[i-1] >= s {
			return false
		}
	}
	return true
}
func nilRef(v References) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func Compile(raw []byte, identities *identity.Catalog, refs References) (*Catalog, error) {
	if len(raw) < 1 || len(raw) > 1<<20 || identities == nil || nilRef(refs) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := strictjson.ReadValue(d, 0, 16)
	if e != nil {
		return nil, ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	var s Source
	if strictjson.ExactDecode(v, &s) != nil || s.APIVersion != APIVersion || s.Kind != Kind || len(s.Clients) < 1 || len(s.Clients) > 128 {
		return nil, ErrInvalid
	}
	profiles := map[string]bool{}
	for _, p := range identities.Source().Profiles {
		profiles[p.ID] = p.Kind == identity.AzureHuman || p.Kind == identity.PrivadoIdentity || p.Kind == identity.PrivadoRole
	}
	c := &Catalog{index: map[string]int{}, identityDigest: identities.Digest()}
	prev := ""
	for i, x := range s.Clients {
		if len(x.ID) > 128 || !name.MatchString(x.ID) || x.ID <= prev || x.Authentication != "client_secret_basic" || x.TrustMode != "first-party-full-core-bearer" || len(x.Secret.FromEnv) > 128 || !env.MatchString(x.Secret.FromEnv) || len(x.DisplayName) < 1 || len(x.DisplayName) > 128 || !utf8.ValidString(x.DisplayName) {
			return nil, ErrInvalid
		}
		for _, r := range x.DisplayName {
			if unicode.IsControl(r) {
				return nil, ErrInvalid
			}
		}
		prev = x.ID
		if len(x.TrustedOrganizationIDs) > 128 || !sorted(x.TrustedOrganizationIDs) || len(x.EligibleGroups) > 32 || len(x.AllowedProfiles) < 1 || len(x.AllowedProfiles) > 16 || !sorted(x.AllowedProfiles) || len(x.RedirectURIs) < 1 || len(x.RedirectURIs) > 16 || !sorted(x.RedirectURIs) {
			return nil, ErrInvalid
		}
		orgs := map[string]bool{}
		for _, o := range x.TrustedOrganizationIDs {
			if !uuid(o) || !refs.Organization(o) {
				return nil, ErrInvalid
			}
			orgs[o] = true
		}
		switch x.Eligibility {
		case GroupEligibility:
			if len(x.EligibleGroups) == 0 {
				return nil, ErrInvalid
			}
		case ProfileEligibility:
			if len(x.EligibleGroups) != 0 {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
		for j, g := range x.EligibleGroups {
			if !uuid(g.OrganizationID) || !uuid(g.GroupID) || !orgs[g.OrganizationID] || !refs.Group(g.OrganizationID, g.GroupID) || j > 0 && (x.EligibleGroups[j-1].OrganizationID > g.OrganizationID || x.EligibleGroups[j-1].OrganizationID == g.OrganizationID && x.EligibleGroups[j-1].GroupID >= g.GroupID) {
				return nil, ErrInvalid
			}
		}
		for _, p := range x.AllowedProfiles {
			if !profiles[p] {
				return nil, ErrInvalid
			}
		}
		for _, u := range x.RedirectURIs {
			if !redirect(u) {
				return nil, ErrInvalid
			}
		}
		c.index[x.ID] = i
		c.clients = append(c.clients, Client{clone(x)})
	}
	sum := sha256.Sum256(raw)
	c.digest = "sha256:" + hex.EncodeToString(sum[:])
	return c, nil
}
func redirect(raw string) bool {
	if len(raw) < 1 || len(raw) > 2048 || strings.ContainsAny(raw, "%\\ \t\r\n") {
		return false
	}
	for _, b := range []byte(raw) {
		if b < 33 || b > 126 {
			return false
		}
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Path == "" || u.Path[0] != '/' || u.String() != raw || path.Clean(u.Path) != u.Path || strings.Contains(u.Path, "//") {
		return false
	}
	for _, b := range []byte(u.Path) {
		if !(b == '/' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b))) {
			return false
		}
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.String() != host {
			return false
		}
	} else {
		labels := strings.Split(host, ".")
		last := labels[len(labels)-1]
		// Browsers parse numeric-ending names as IPv4, including abbreviated,
		// octal and hexadecimal forms which net.ParseIP does not accept.
		if len(host) > 253 || last == "" || strings.HasPrefix(last, "0x") {
			return false
		}
		numeric := true
		for _, b := range []byte(last) {
			numeric = numeric && b >= '0' && b <= '9'
		}
		if numeric {
			return false
		}
		for _, l := range labels {
			if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
				return false
			}
			for _, b := range []byte(l) {
				if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
					return false
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false
	}
	return true
}
