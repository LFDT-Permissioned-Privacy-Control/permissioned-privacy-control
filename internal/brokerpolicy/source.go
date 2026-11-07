// Package brokerpolicy compiles public approved broker bindings. It owns no
// private key, provider connection, session storage or environment lookup.
package brokerpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
)

const (
	APIVersion     = "ops.auth-broker/v1alpha1"
	Kind           = "AuthBroker"
	MaxSourceBytes = 256 << 10
	MaxProfiles    = 64
)

var ErrInvalid = errors.New("invalid approved auth broker")

type SecretRef struct {
	FromEnv string `json:"fromEnv"`
}
type KeyRef struct {
	ID      string `json:"id"`
	FromEnv string `json:"fromEnv"`
	Active  bool   `json:"active"`
}
type AzureBinding struct {
	ProfileID    string     `json:"profileId"`
	RedirectURI  string     `json:"redirectUri,omitempty" optional:"true"`
	ClientSecret *SecretRef `json:"clientSecret,omitempty" optional:"true"`
}
type Source struct {
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	IssuerID       string         `json:"issuerId"`
	AccessKeyID    string         `json:"accessKeyId"`
	WebOrigin      string         `json:"webOrigin"`
	CompletionURI  string         `json:"completionUri"`
	AzureProfiles  []AzureBinding `json:"azureProfiles"`
	RenewalKeys    []KeyRef       `json:"renewalKeys"`
	EncryptionKeys []KeyRef       `json:"encryptionKeys"`
}

func Decode(raw []byte) (Source, error) {
	if len(raw) == 0 || len(raw) > MaxSourceBytes || !utf8.Valid(raw) {
		return Source{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := strictjson.ReadValue(d, 0, 16)
	if err != nil {
		return Source{}, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return Source{}, ErrInvalid
	}
	object, ok := value.(map[string]any)
	if !ok {
		return Source{}, ErrInvalid
	}
	for key, max := range map[string]int{"azureProfiles": MaxProfiles, "renewalKeys": 2, "encryptionKeys": 2} {
		values, ok := object[key].([]any)
		if !ok || len(values) > max {
			return Source{}, ErrInvalid
		}
	}
	var source Source
	if strictjson.ExactDecode(value, &source) != nil {
		return Source{}, ErrInvalid
	}
	return source, nil
}

type Profile struct {
	Definition identity.Profile
	Binding    AzureBinding
	Digest     string
	ScopeWord  string
}
type Catalog struct {
	source                 Source
	multi                  *SourceV2
	documents              []DocumentBytes
	digest, identityDigest string
	issuer                 identity.Issuer
	profiles               map[string]Profile
	capabilities, refs     []string
}

func (c *Catalog) Digest() string         { return c.digest }
func (c *Catalog) IdentityDigest() string { return c.identityDigest }

// Source returns only the legacy source variant. Use SourceV1 or MultiSource
// when the variant is not already fixed by a compiled validation profile.
func (c *Catalog) Source() Source                    { return clone(c.source) }
func (c *Catalog) Issuer() identity.Issuer           { return clone(c.issuer) }
func (c *Catalog) Profile(id string) (Profile, bool) { p, ok := c.profiles[id]; return clone(p), ok }
func (c *Catalog) Profiles() []Profile {
	out := make([]Profile, 0, len(c.profiles))
	for _, p := range c.profiles {
		out = append(out, clone(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Definition.ID < out[j].Definition.ID })
	return out
}
func (c *Catalog) Requirements() ([]string, []string) {
	return slices.Clone(c.capabilities), slices.Clone(c.refs)
}
func clone[T any](value T) T {
	raw, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func text(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var envName = regexp.MustCompile(`^OPS_BROKER_[A-Z0-9_]+$`)

func ref(raw, prefix string) bool {
	return len(raw) <= 80 && strings.HasPrefix(raw, prefix) && len(raw) > len(prefix) && envName.MatchString(raw)
}
func https(raw string, origin bool) (string, bool) {
	if !text(raw, 2048) || strings.Contains(raw, "#") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	if origin {
		if u.RawQuery != "" || u.Path != "" && u.Path != "/" {
			return "", false
		}
		u.Path = ""
		u.RawPath = ""
		u.ForceQuery = false
	}
	return u.String(), true
}
func Compile(source Source, identities *identity.Catalog) (*Catalog, error) {
	return compile(source, identities, false)
}

func compile(source Source, identities *identity.Catalog, allowEmptyAzure bool) (*Catalog, error) {
	if identities == nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, ErrInvalid
	}
	source, err = Decode(raw)
	if err != nil {
		return nil, err
	}
	if source.APIVersion != APIVersion || source.Kind != Kind || !identifier.MatchString(source.IssuerID) || !identifier.MatchString(source.AccessKeyID) || len(source.AzureProfiles) == 0 && !allowEmptyAzure {
		return nil, ErrInvalid
	}
	origin, ok := https(source.WebOrigin, true)
	if !ok {
		return nil, ErrInvalid
	}
	completion, ok := https(source.CompletionURI, false)
	if !ok {
		return nil, ErrInvalid
	}
	u, _ := url.Parse(completion)
	if u.Scheme+"://"+u.Host != origin {
		return nil, ErrInvalid
	}
	source.WebOrigin = origin
	source.CompletionURI = completion
	idSource := identities.Source()
	var issuer identity.Issuer
	for _, candidate := range idSource.Issuers {
		if candidate.ID == source.IssuerID {
			issuer = candidate
		}
	}
	if issuer.ID == "" {
		return nil, ErrInvalid
	}
	foundKey := false
	for _, key := range issuer.Keys {
		foundKey = foundKey || key.Kid == source.AccessKeyID
	}
	if !foundKey {
		return nil, ErrInvalid
	}
	profiles := map[string]identity.Profile{}
	for _, profile := range idSource.Profiles {
		profiles[profile.ID] = profile
	}
	c := &Catalog{identityDigest: identities.Digest(), issuer: issuer, profiles: map[string]Profile{}}
	caps := map[string]bool{"operational.identity-session/v1": true, "secrets.ops-access-signing/v1": true}
	refs := map[string]bool{}
	for i := range source.AzureProfiles {
		binding := &source.AzureProfiles[i]
		profile, ok := profiles[binding.ProfileID]
		if !ok || !slices.Contains(issuer.AllowedProfiles, binding.ProfileID) || c.profiles[binding.ProfileID].Digest != "" {
			return nil, ErrInvalid
		}
		switch profile.Kind {
		case identity.AzureHuman:
			redirect, valid := https(binding.RedirectURI, false)
			if !valid || binding.ClientSecret == nil || !ref(binding.ClientSecret.FromEnv, "OPS_BROKER_AZURE_") {
				return nil, ErrInvalid
			}
			binding.RedirectURI = redirect
			refs[binding.ClientSecret.FromEnv] = true
			caps["provider.azure-grant/v1"] = true
		case identity.AzureService:
			if binding.RedirectURI != "" || binding.ClientSecret != nil {
				return nil, ErrInvalid
			}
			caps["provider.azure-token/v1"] = true
		default:
			return nil, ErrInvalid
		}
		profileDigest, _ := identities.ProfileDigest(profile.ID)
		word := ""
		if profile.Kind == identity.AzureHuman {
			var valid bool
			word, valid = scopeWord(profile.DelegatedScope)
			if !valid {
				return nil, ErrInvalid
			}
		}
		c.profiles[profile.ID] = Profile{profile, *binding, profileDigest, word}
	}
	if !keys(source.RenewalKeys, "OPS_BROKER_REFRESH_", refs) || !keys(source.EncryptionKeys, "OPS_BROKER_ENCRYPTION_", refs) {
		return nil, ErrInvalid
	}
	sort.Slice(source.AzureProfiles, func(i, j int) bool { return source.AzureProfiles[i].ProfileID < source.AzureProfiles[j].ProfileID })
	sort.Slice(source.RenewalKeys, func(i, j int) bool { return source.RenewalKeys[i].ID < source.RenewalKeys[j].ID })
	sort.Slice(source.EncryptionKeys, func(i, j int) bool { return source.EncryptionKeys[i].ID < source.EncryptionKeys[j].ID })
	for cap := range caps {
		c.capabilities = append(c.capabilities, cap)
	}
	for ref := range refs {
		c.refs = append(c.refs, ref)
	}
	sort.Strings(c.capabilities)
	sort.Strings(c.refs)
	c.source = source
	encoded, _ := json.Marshal(source)
	hash := sha256.Sum256(encoded)
	c.digest = "sha256:" + hex.EncodeToString(hash[:])
	return c, nil
}

// Request the full resource-qualified scope unchanged, but match the terminal
// scope value carried in the signed access token's space-delimited scp claim.
func scopeWord(raw string) (string, bool) {
	if !text(raw, 2048) || strings.ContainsAny(raw, " \t\r\n%#") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "api" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Path == "" || strings.HasSuffix(u.Path, "/") {
		return "", false
	}
	word := u.Path[strings.LastIndex(u.Path, "/")+1:]
	if len(word) == 0 || len(word) > 128 || word == ".default" {
		return "", false
	}
	for _, b := range []byte(word) {
		if !(b == 0x21 || b >= 0x23 && b <= 0x5b || b >= 0x5d && b <= 0x7e) || b == '/' || b == '?' || b == '#' || b == '%' {
			return "", false
		}
	}
	return word, true
}
func keys(rows []KeyRef, prefix string, refs map[string]bool) bool {
	if len(rows) == 0 || len(rows) > 2 {
		return false
	}
	ids := map[string]bool{}
	active := 0
	for _, key := range rows {
		if !identifier.MatchString(key.ID) || ids[key.ID] || !ref(key.FromEnv, prefix) || refs[key.FromEnv] {
			return false
		}
		ids[key.ID] = true
		refs[key.FromEnv] = true
		if key.Active {
			active++
		}
	}
	return active == 1
}
