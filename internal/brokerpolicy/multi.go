package brokerpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
)

const MultiAPIVersion = "ops.auth-broker/v1alpha2"
const MaxPinnedDocumentBytes = 1 << 20
const MaxPinnedDocumentsBytes = 2 << 20

type PrivadoBinding struct {
	ProfileID string `json:"profileId"`
}
type RPCCredentialRef struct {
	FromEnv string `json:"fromEnv"`
	Header  string `json:"header"`
}
type PrivadoNetwork struct {
	Network       string            `json:"network"`
	ChainID       string            `json:"chainId"`
	StateContract string            `json:"stateContract"`
	RPCURL        string            `json:"rpcUrl"`
	AllowPrivate  bool              `json:"allowPrivate"`
	Credential    *RPCCredentialRef `json:"credential,omitempty" optional:"true"`
}
type PinnedDocumentRef struct {
	URL    string `json:"url"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// SourceV2 is a separate closed source variant. An identity profile alone never
// activates an external provider or adds a network destination.
type SourceV2 struct {
	APIVersion      string              `json:"apiVersion"`
	Kind            string              `json:"kind"`
	IssuerID        string              `json:"issuerId"`
	AccessKeyID     string              `json:"accessKeyId"`
	WebOrigin       string              `json:"webOrigin"`
	CompletionURI   string              `json:"completionUri"`
	AzureProfiles   []AzureBinding      `json:"azureProfiles"`
	PrivadoProfiles []PrivadoBinding    `json:"privadoProfiles"`
	PrivadoNetworks []PrivadoNetwork    `json:"privadoNetworks"`
	PinnedDocuments []PinnedDocumentRef `json:"pinnedDocuments"`
	RenewalKeys     []KeyRef            `json:"renewalKeys"`
	EncryptionKeys  []KeyRef            `json:"encryptionKeys"`
}
type CommonSettings struct {
	IssuerID, AccessKeyID, WebOrigin, CompletionURI string
	RenewalKeys, EncryptionKeys                     []KeyRef
}
type DocumentBytes struct {
	URL      string
	RawBytes []byte
}

func (c *Catalog) SourceV1() (Source, bool) {
	if c == nil || c.multi != nil {
		return Source{}, false
	}
	return clone(c.source), true
}
func (c *Catalog) MultiSource() (SourceV2, bool) {
	if c == nil || c.multi == nil {
		return SourceV2{}, false
	}
	return clone(*c.multi), true
}
func (c *Catalog) CommonSettings() CommonSettings {
	if c == nil {
		return CommonSettings{}
	}
	s := c.source
	if c.multi != nil {
		v := c.multi
		return CommonSettings{v.IssuerID, v.AccessKeyID, v.WebOrigin, v.CompletionURI, clone(v.RenewalKeys), clone(v.EncryptionKeys)}
	}
	return CommonSettings{s.IssuerID, s.AccessKeyID, s.WebOrigin, s.CompletionURI, clone(s.RenewalKeys), clone(s.EncryptionKeys)}
}
func (c *Catalog) PinnedDocuments() []DocumentBytes {
	if c == nil {
		return nil
	}
	out := make([]DocumentBytes, len(c.documents))
	for i, d := range c.documents {
		out[i] = DocumentBytes{d.URL, bytes.Clone(d.RawBytes)}
	}
	return out
}
func DecodeV2(raw []byte) (SourceV2, error) {
	if len(raw) == 0 || len(raw) > MaxSourceBytes || !utf8.Valid(raw) {
		return SourceV2{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, 16)
	if err != nil {
		return SourceV2{}, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return SourceV2{}, ErrInvalid
	}
	o, ok := v.(map[string]any)
	if !ok {
		return SourceV2{}, ErrInvalid
	}
	for key, max := range map[string]int{"azureProfiles": MaxProfiles, "privadoProfiles": MaxProfiles, "privadoNetworks": 8, "pinnedDocuments": 16, "renewalKeys": 2, "encryptionKeys": 2} {
		a, ok := o[key].([]any)
		if !ok || len(a) > max {
			return SourceV2{}, ErrInvalid
		}
	}
	var s SourceV2
	if strictjson.ExactDecode(v, &s) != nil || s.APIVersion != MultiAPIVersion || s.Kind != Kind {
		return SourceV2{}, ErrInvalid
	}
	return s, nil
}

var pinnedPath = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*\.json$`)
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var stateAddress = regexp.MustCompile(`^0x[0-9a-f]{40}$`)

func canonicalHTTPS(raw string) bool {
	if !text(raw, 2048) || strings.ContainsAny(raw, "\\#") || strings.TrimSpace(raw) != raw {
		return false
	}
	for _, b := range []byte(raw) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && u.User == nil && u.Opaque == "" && u.Fragment == "" && !u.ForceQuery && u.RawQuery == "" && u.String() == raw
}
func networkForDID(raw string) (string, bool) {
	d, e := w3c.ParseDID(raw)
	if e != nil || d.String() != raw {
		return "", false
	}
	id, e := core.IDFromDID(*d)
	if e != nil {
		return "", false
	}
	canonical, e := core.ParseDIDFromID(id)
	if e != nil || canonical.String() != raw {
		return "", false
	}
	b, e := core.BlockchainFromID(id)
	if e != nil {
		return "", false
	}
	n, e := core.NetworkIDFromID(id)
	return string(b) + ":" + string(n), e == nil
}
func rpcHeader(raw string) bool {
	if raw == "" || len(raw) > 128 || textproto.CanonicalMIMEHeaderKey(raw) != raw {
		return false
	}
	for _, c := range raw {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	switch strings.ToLower(raw) {
	case "host", "cookie", "content-length", "content-type", "connection", "transfer-encoding", "accept-encoding", "proxy-authorization", "origin", "referer":
		return false
	}
	return true
}
func CompileV2(source SourceV2, identities *identity.Catalog, documents []DocumentBytes) (*Catalog, error) {
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, ErrInvalid
	}
	source, err = DecodeV2(raw)
	if err != nil || identities == nil || len(source.PrivadoProfiles) == 0 || len(source.AzureProfiles)+len(source.PrivadoProfiles) > MaxProfiles {
		return nil, ErrInvalid
	}
	// The common validator is internal; its legacy source is never exposed as a
	// projection of a multi-source catalog.
	base := Source{APIVersion, source.Kind, source.IssuerID, source.AccessKeyID, source.WebOrigin, source.CompletionURI, source.AzureProfiles, source.RenewalKeys, source.EncryptionKeys}
	c, err := compile(base, identities, true)
	if err != nil {
		return nil, err
	}
	source.WebOrigin = c.source.WebOrigin
	source.CompletionURI = c.source.CompletionURI
	source.AzureProfiles = c.source.AzureProfiles
	source.RenewalKeys = c.source.RenewalKeys
	source.EncryptionKeys = c.source.EncryptionKeys
	profiles := map[string]identity.Profile{}
	for _, p := range identities.Source().Profiles {
		profiles[p.ID] = p
	}
	seen := map[string]bool{}
	needed := map[string]bool{}
	for _, b := range source.AzureProfiles {
		seen[b.ProfileID] = true
	}
	for _, b := range source.PrivadoProfiles {
		p, ok := profiles[b.ProfileID]
		if !ok || seen[b.ProfileID] || !slices.Contains(c.issuer.AllowedProfiles, b.ProfileID) || (p.Kind != identity.PrivadoIdentity && p.Kind != identity.PrivadoRole) {
			return nil, ErrInvalid
		}
		seen[b.ProfileID] = true
		needed[p.Network] = true
		for _, did := range p.AllowedCredentialIssuers {
			network, ok := networkForDID(did)
			if !ok {
				return nil, ErrInvalid
			}
			needed[network] = true
		}
	}
	if len(needed) != len(source.PrivadoNetworks) {
		return nil, ErrInvalid
	}
	networks := map[string]PrivadoNetwork{}
	refs := map[string]bool{}
	for _, r := range c.refs {
		refs[r] = true
	}
	for _, n := range source.PrivadoNetworks {
		chain, ok := new(big.Int).SetString(n.ChainID, 10)
		if !needed[n.Network] || networks[n.Network].Network != "" || !canonicalHTTPS(n.RPCURL) || !stateAddress.MatchString(n.StateContract) || n.StateContract == "0x"+strings.Repeat("0", 40) || !ok || chain.Sign() <= 0 || chain.BitLen() > 256 || chain.String() != n.ChainID {
			return nil, ErrInvalid
		}
		if n.Credential != nil {
			if !ref(n.Credential.FromEnv, "OPS_BROKER_PRIVADO_") || !rpcHeader(n.Credential.Header) {
				return nil, ErrInvalid
			}
			refs[n.Credential.FromEnv] = true
		}
		networks[n.Network] = n
	}
	for _, b := range source.PrivadoProfiles {
		p := profiles[b.ProfileID]
		if networks[p.Network].StateContract != p.IdentityStateContract {
			return nil, ErrInvalid
		}
	}
	if len(documents) != len(source.PinnedDocuments) {
		return nil, ErrInvalid
	}
	docs := map[string][]byte{}
	for _, d := range documents {
		if _, ok := docs[d.URL]; ok {
			return nil, ErrInvalid
		}
		docs[d.URL] = d.RawBytes
	}
	paths := map[string]bool{}
	urls := map[string]bool{}
	total := 0
	for _, r := range source.PinnedDocuments {
		data, ok := docs[r.URL]
		sum := sha256.Sum256(data)
		if !ok || urls[r.URL] || paths[r.Path] || !canonicalHTTPS(r.URL) || len(r.Path) > 128 || !pinnedPath.MatchString(r.Path) || r.Path == "manifest.json" || r.Path == "draft.json" || !digestPattern.MatchString(r.SHA256) || r.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) || len(data) == 0 || len(data) > MaxPinnedDocumentBytes || len(data) > MaxPinnedDocumentsBytes-total || !utf8.Valid(data) {
			return nil, ErrInvalid
		}
		var object map[string]any
		if json.Unmarshal(data, &object) != nil || object == nil {
			return nil, ErrInvalid
		}
		total += len(data)
		paths[r.Path] = true
		urls[r.URL] = true
		c.documents = append(c.documents, DocumentBytes{r.URL, bytes.Clone(data)})
	}
	for _, b := range source.PrivadoProfiles {
		p := profiles[b.ProfileID]
		if p.Kind == identity.PrivadoRole {
			data, ok := docs[p.Context]
			sum := sha256.Sum256(data)
			if !ok || p.ContextDigest != "sha256:"+hex.EncodeToString(sum[:]) {
				return nil, ErrInvalid
			}
		}
	}
	sort.Slice(source.PrivadoProfiles, func(i, j int) bool { return source.PrivadoProfiles[i].ProfileID < source.PrivadoProfiles[j].ProfileID })
	sort.Slice(source.PrivadoNetworks, func(i, j int) bool { return source.PrivadoNetworks[i].Network < source.PrivadoNetworks[j].Network })
	sort.Slice(source.PinnedDocuments, func(i, j int) bool { return source.PinnedDocuments[i].URL < source.PinnedDocuments[j].URL })
	sort.Slice(c.documents, func(i, j int) bool { return c.documents[i].URL < c.documents[j].URL })
	c.capabilities = append(c.capabilities, "provider.privado-proof/v1")
	sort.Strings(c.capabilities)
	c.refs = nil
	for r := range refs {
		c.refs = append(c.refs, r)
	}
	sort.Strings(c.refs)
	c.source = Source{}
	c.multi = &source
	encoded, _ := json.Marshal(source)
	sum := sha256.Sum256(encoded)
	c.digest = "sha256:" + hex.EncodeToString(sum[:])
	return c, nil
}
