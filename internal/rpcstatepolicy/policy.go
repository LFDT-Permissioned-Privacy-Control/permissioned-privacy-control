// Package rpcstatepolicy compiles only approved state-read configuration. It
// supplies no principal, SQL setting, target-data ownership or public fallback.
package rpcstatepolicy

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

	m "privacy-proxy/internal/rpcmetadatapolicy"
)

type Digest = m.Digest

const APIVersion = "ops.rpc-state-policy/v1"
const Kind = "StatePolicy"

var ErrInvalid = errors.New("invalid state policy")

type PreRegisteredAddress struct {
	Address        string `json:"address"`
	OrganizationID string `json:"organizationId"`
}
type Source struct {
	APIVersion             string                 `json:"apiVersion"`
	Kind                   string                 `json:"kind"`
	BundleManifestDigest   string                 `json:"bundleManifestDigest"`
	AnonymousMethods       []string               `json:"anonymousMethods"`
	PreRegisteredAddresses []PreRegisteredAddress `json:"preRegisteredAddresses"`
	LinkedWalletBasics     bool                   `json:"linkedWalletBasics,omitempty"`
}
type Definition struct {
	manifest, digest   Digest
	anonymous          []string
	preregistered      []PreRegisteredAddress
	linkedWalletBasics bool
}

var orgID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var address = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
var stateNames = map[string]bool{"eth_getBalance": true, "eth_getCode": true, "eth_getStorageAt": true, "eth_getProof": true, "eth_getTransactionCount": true}

func anonymousName(name string) bool {
	return name == "eth_getBalance" || name == "eth_getCode" || name == "eth_getTransactionCount"
}
func parseDigest(s string) (Digest, bool) {
	var d Digest
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return d, false
	}
	raw, err := hex.DecodeString(s[7:])
	if err != nil || hex.EncodeToString(raw) != s[7:] {
		return d, false
	}
	copy(d[:], raw)
	return d, d != (Digest{})
}
func readString(d *json.Decoder) (string, error) {
	v, e := d.Token()
	s, ok := v.(string)
	if e != nil || !ok {
		return "", ErrInvalid
	}
	return s, nil
}
func Compile(raw []byte, expectedRawSHA Digest) (*Definition, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) || expectedRawSHA == (Digest{}) || Digest(sha256.Sum256(raw)) != expectedRawSHA {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	s := Source{AnonymousMethods: []string{}, PreRegisteredAddresses: []PreRegisteredAddress{}}
	seen := map[string]bool{}
	for d.More() {
		name, err := readString(d)
		if err != nil || seen[name] {
			return nil, ErrInvalid
		}
		seen[name] = true
		switch name {
		case "linkedWalletBasics":
			token, err := d.Token()
			value, ok := token.(bool)
			if err != nil || !ok {
				return nil, ErrInvalid
			}
			s.LinkedWalletBasics = value
		case "apiVersion", "kind", "bundleManifestDigest":
			value, err := readString(d)
			if err != nil {
				return nil, err
			}
			switch name {
			case "apiVersion":
				s.APIVersion = value
			case "kind":
				s.Kind = value
			default:
				s.BundleManifestDigest = value
			}
		case "anonymousMethods":
			if v, e := d.Token(); e != nil || v != json.Delim('[') {
				return nil, ErrInvalid
			}
			names := map[string]bool{}
			for d.More() {
				value, e := readString(d)
				if e != nil || !anonymousName(value) || names[value] || len(names) >= 3 {
					return nil, ErrInvalid
				}
				names[value] = true
				s.AnonymousMethods = append(s.AnonymousMethods, value)
			}
			if v, e := d.Token(); e != nil || v != json.Delim(']') {
				return nil, ErrInvalid
			}
		case "preRegisteredAddresses":
			if v, e := d.Token(); e != nil || v != json.Delim('[') {
				return nil, ErrInvalid
			}
			addresses := map[string]bool{}
			for d.More() {
				if len(s.PreRegisteredAddresses) >= 256 {
					return nil, ErrInvalid
				}
				if v, e := d.Token(); e != nil || v != json.Delim('{') {
					return nil, ErrInvalid
				}
				entry := PreRegisteredAddress{}
				fields := map[string]bool{}
				for d.More() {
					key, e := readString(d)
					if e != nil || fields[key] {
						return nil, ErrInvalid
					}
					fields[key] = true
					value, e := readString(d)
					if e != nil {
						return nil, ErrInvalid
					}
					switch key {
					case "address":
						entry.Address = strings.ToLower(value)
					case "organizationId":
						entry.OrganizationID = value
					default:
						return nil, ErrInvalid
					}
				}
				if v, e := d.Token(); e != nil || v != json.Delim('}') || len(fields) != 2 || !address.MatchString(entry.Address) || entry.Address == "0x"+strings.Repeat("0", 40) || !orgID.MatchString(entry.OrganizationID) || entry.OrganizationID == "00000000-0000-0000-0000-000000000000" || addresses[entry.Address] {
					return nil, ErrInvalid
				}
				addresses[entry.Address] = true
				s.PreRegisteredAddresses = append(s.PreRegisteredAddresses, entry)
			}
			if v, e := d.Token(); e != nil || v != json.Delim(']') {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
	}
	if v, e := d.Token(); e != nil || v != json.Delim('}') || len(seen) < 5 || len(seen) > 6 || !seen["apiVersion"] || !seen["kind"] || !seen["bundleManifestDigest"] || !seen["anonymousMethods"] || !seen["preRegisteredAddresses"] || s.APIVersion != APIVersion || s.Kind != Kind {
		return nil, ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	manifest, ok := parseDigest(s.BundleManifestDigest)
	if !ok {
		return nil, ErrInvalid
	}
	sort.Strings(s.AnonymousMethods)
	sort.Slice(s.PreRegisteredAddresses, func(i, j int) bool { return s.PreRegisteredAddresses[i].Address < s.PreRegisteredAddresses[j].Address })
	canonical, err := json.Marshal(s)
	if err != nil {
		return nil, ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("ops-rpc-state-policy/v1\x00"))
	h.Write(canonical)
	var digest Digest
	copy(digest[:], h.Sum(nil))
	return &Definition{manifest, digest, s.AnonymousMethods, s.PreRegisteredAddresses, s.LinkedWalletBasics}, nil
}
func (d *Definition) LinkedWalletBasicsEnabled() bool { return d != nil && d.linkedWalletBasics }
func (d *Definition) ManifestDigest() Digest {
	if d == nil {
		return Digest{}
	}
	return d.manifest
}
func (d *Definition) PreRegisteredAddresses() []PreRegisteredAddress {
	if d == nil {
		return nil
	}
	return slices.Clone(d.preregistered)
}

type Policy struct {
	definition *Definition
	digest     Digest
	methods    []m.Method
}

func Bind(d *Definition, manifest Digest, version string, methods []m.Method) (*Policy, error) {
	if d == nil || manifest != d.manifest || manifest == (Digest{}) {
		return nil, ErrInvalid
	}
	owned, methodDigest, err := m.BindMethods(version, methods)
	if err != nil {
		return nil, ErrInvalid
	}
	selected := []m.Method{}
	for _, method := range owned {
		if stateNames[method.Canonical] {
			selected = append(selected, method)
		}
	}
	h := sha256.New()
	h.Write([]byte("ops-rpc-state-permission/v1\x00"))
	h.Write(manifest[:])
	h.Write(d.digest[:])
	h.Write(methodDigest[:])
	var digest Digest
	copy(digest[:], h.Sum(nil))
	return &Policy{d, digest, selected}, nil
}
func (p *Policy) Digest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.digest
}
func (p *Policy) AllowsAnonymous(name string) bool {
	return p != nil && p.definition != nil && anonymousName(name) && slices.Contains(p.definition.anonymous, name)
}
func (p *Policy) Methods() []m.Method {
	if p == nil {
		return nil
	}
	out := slices.Clone(p.methods)
	for i := range out {
		out[i].RequiredClaims = slices.Clone(out[i].RequiredClaims)
	}
	return out
}
