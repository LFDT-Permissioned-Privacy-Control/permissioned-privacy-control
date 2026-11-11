// Package rpcmetadatapolicy compiles the selected metadata-only anonymous rule
// and binds its digest to the actual method catalog. It grants no identity.
package rpcmetadatapolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

type Digest [32]byte

var ErrInvalid = errors.New("invalid metadata policy")

const APIVersion = "ops.rpc-metadata-policy/v1"
const Kind = "MetadataPolicy"

type Source struct {
	APIVersion           string   `json:"apiVersion"`
	Kind                 string   `json:"kind"`
	BundleManifestDigest string   `json:"bundleManifestDigest"`
	AnonymousMethods     []string `json:"anonymousMethods"`
}

type Definition struct {
	manifest  Digest
	digest    Digest
	anonymous []string
}

var metadataNames = map[string]bool{
	"eth_accounts": true, "eth_blockNumber": true, "eth_chainId": true,
	"eth_feeHistory": true, "eth_gasPrice": true, "eth_maxPriorityFeePerGas": true,
	"eth_syncing": true, "net_listening": true, "net_peerCount": true,
	"net_version": true, "web3_clientVersion": true, "web3_sha3": true,
}

// Compile checks bytes against an expected raw SHA, which does not itself prove
// Git approval. Trusted startup assembly supplies the approved selection.
func Compile(raw []byte, expectedRawSHA Digest) (*Definition, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) || expectedRawSHA == (Digest{}) || Digest(sha256.Sum256(raw)) != expectedRawSHA {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	source := Source{AnonymousMethods: []string{}}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return nil, ErrInvalid
		}
		seen[name] = true
		switch name {
		case "apiVersion", "kind", "bundleManifestDigest":
			token, err = d.Token()
			value, ok := token.(string)
			if err != nil || !ok {
				return nil, ErrInvalid
			}
			switch name {
			case "apiVersion":
				source.APIVersion = value
			case "kind":
				source.Kind = value
			default:
				source.BundleManifestDigest = value
			}
		case "anonymousMethods":
			token, err = d.Token()
			if err != nil || token != json.Delim('[') {
				return nil, ErrInvalid
			}
			names := map[string]bool{}
			for d.More() {
				if len(source.AnonymousMethods) >= len(metadataNames) {
					return nil, ErrInvalid
				}
				token, err = d.Token()
				value, ok := token.(string)
				if err != nil || !ok || !metadataNames[value] || names[value] {
					return nil, ErrInvalid
				}
				names[value] = true
				source.AnonymousMethods = append(source.AnonymousMethods, value)
			}
			if token, err = d.Token(); err != nil || token != json.Delim(']') {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(seen) != 4 {
		return nil, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF || source.APIVersion != APIVersion || source.Kind != Kind {
		return nil, ErrInvalid
	}
	manifest, ok := parseDigest(source.BundleManifestDigest)
	if !ok {
		return nil, ErrInvalid
	}
	sort.Strings(source.AnonymousMethods)
	canonical, _ := json.Marshal(source)
	digest := hash("ops-rpc-metadata-policy/v1", canonical)
	return &Definition{manifest, digest, source.AnonymousMethods}, nil
}

func (d *Definition) Digest() Digest {
	if d == nil {
		return Digest{}
	}
	return d.digest
}
func (d *Definition) ManifestDigest() Digest {
	if d == nil {
		return Digest{}
	}
	return d.manifest
}
func (d *Definition) AnonymousMethods() []string {
	if d == nil {
		return nil
	}
	return slices.Clone(d.anonymous)
}

type Method struct {
	Name           string   `json:"name"`
	Canonical      string   `json:"canonical"`
	RequiredClaims []string `json:"requiredClaims"`
}
type Policy struct {
	digest, methods Digest
	definition      *Definition
	metadata        []Method
}

var methodName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*_[a-zA-Z][a-zA-Z0-9_]*$`)

// Bind includes every selected method, including declarations that this engine
// does not dispatch. Concrete engine startup separately checks alias namespaces
// and all original builtin names through the pure rpcmethoddata catalog.
func Bind(d *Definition, manifest Digest, methodCatalogVersion string, methods []Method) (*Policy, error) {
	if d == nil || d.digest == (Digest{}) || manifest == (Digest{}) || manifest != d.manifest || !validText(methodCatalogVersion, 128) || len(methods) == 0 {
		return nil, ErrInvalid
	}
	owned := make([]Method, len(methods))
	index := make(map[string]int, len(methods))
	for i, m := range methods {
		if !methodName.MatchString(m.Name) || !methodName.MatchString(m.Canonical) {
			return nil, ErrInvalid
		}
		if _, duplicate := index[m.Name]; duplicate {
			return nil, ErrInvalid
		}
		index[m.Name] = i
		m.RequiredClaims = append([]string{}, m.RequiredClaims...)
		sort.Strings(m.RequiredClaims)
		for j, claim := range m.RequiredClaims {
			if claim != "admin" && claim != "deploy" && claim != "upgrade" || j > 0 && m.RequiredClaims[j-1] == claim {
				return nil, ErrInvalid
			}
		}
		owned[i] = m
	}
	for _, m := range owned {
		i, known := index[m.Canonical]
		if !known || owned[i].Canonical != m.Canonical {
			return nil, ErrInvalid
		}
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].Name < owned[j].Name })
	h := sha256.New()
	_, _ = h.Write([]byte("ops-rpc-metadata-method-set/v1\x00{\"version\":"))
	version, _ := json.Marshal(methodCatalogVersion)
	_, _ = h.Write(version)
	_, _ = h.Write([]byte(",\"methods\":["))
	metadata := []Method{}
	for i, m := range owned {
		if i != 0 {
			_, _ = h.Write([]byte{','})
		}
		encoded, _ := json.Marshal(m)
		_, _ = h.Write(encoded)
		if metadataNames[m.Canonical] {
			metadata = append(metadata, m)
		}
	}
	_, _ = h.Write([]byte("]}"))
	var methodDigest Digest
	copy(methodDigest[:], h.Sum(nil))
	effective := sha256.New()
	_, _ = effective.Write([]byte("ops-rpc-metadata-permission/v1\x00"))
	_, _ = effective.Write(manifest[:])
	_, _ = effective.Write(d.digest[:])
	_, _ = effective.Write(methodDigest[:])
	var digest Digest
	copy(digest[:], effective.Sum(nil))
	return &Policy{digest, methodDigest, d, metadata}, nil
}

func (p *Policy) Digest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.digest
}
func (p *Policy) MethodSetDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.methods
}
func (p *Policy) AllowsAnonymous(canonicalBuiltin string) bool {
	return p != nil && p.definition != nil && metadataNames[canonicalBuiltin] && slices.Contains(p.definition.anonymous, canonicalBuiltin)
}
func (p *Policy) MetadataMethods() []Method {
	if p == nil {
		return nil
	}
	methods := slices.Clone(p.metadata)
	for i := range methods {
		methods[i].RequiredClaims = slices.Clone(methods[i].RequiredClaims)
	}
	return methods
}
func parseDigest(s string) (Digest, bool) {
	var d Digest
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return d, false
	}
	b, err := hex.DecodeString(s[7:])
	if err != nil || hex.EncodeToString(b) != s[7:] {
		return d, false
	}
	copy(d[:], b)
	return d, d != (Digest{})
}
func hash(domain string, b []byte) Digest {
	h := sha256.New()
	_, _ = h.Write([]byte(domain + "\x00"))
	_, _ = h.Write(b)
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}
func validText(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
