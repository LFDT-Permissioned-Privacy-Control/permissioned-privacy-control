package disclosuredata

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/strictjson"
)

// RetainedContinuation is created only after authenticating the separate dd2
// payload. It does not attest source facts or replace current case permission.
type RetainedContinuation struct {
	continuation Continuation
	basis        RetainedBasis
}

func (c RetainedContinuation) References() []SourceRef { return c.continuation.References() }
func (c RetainedContinuation) Position() Position      { return c.continuation.Position() }
func (c RetainedContinuation) Basis() RetainedBasis    { return c.basis.Clone() }
func (c RetainedContinuation) VerifySourceSet(d Digest) error {
	return c.continuation.VerifySourceSet(d)
}

type retainedCursorPayload struct {
	V        uint8          `json:"v"`
	Binding  string         `json:"b"`
	Set      string         `json:"s"`
	Refs     []cursorRef    `json:"r"`
	Position cursorPosition `json:"p"`
	Expires  string         `json:"exp"`
	Basis    *RetainedBasis `json:"h,omitempty"`
}

func retainedCursorAAD(id string) []byte {
	return framed([]byte("ops.disclosure.retained-data-cursor/v1"), []byte("dd2"), []byte(id))
}

func retainedBindingDigest(plan SourcePlan, b CursorBinding, resource p.Resource) (Digest, error) {
	if !ValidRetainedPlan(plan) || b.BundleDigest != plan.BundleDigest || b.SourcePlanDigest != plan.PlanDigest {
		return "", ErrInvalid
	}
	base, err := bindingDigest(b)
	if err != nil {
		return "", err
	}
	return hashParts("ops.disclosure.retained-cursor-binding/v1", []byte(base), []byte(plan.NetworkKey), []byte(resource)), nil
}

func retainedCursorSelection(plan SourcePlan, resource p.Resource, basis RetainedBasis, refs []SourceRef, position Position) error {
	if !ValidRetainedPlan(plan) || !slices.Contains(plan.Resources, resource) || BasisForResource(resource, basis) != nil || basis.Valid() && basis.NetworkKey != plan.NetworkKey {
		return ErrInvalid
	}
	kinds, err := RequiredKinds(resource)
	if err != nil || len(kinds) != len(refs) || len(refs) < 1 || len(refs) > 5 {
		return ErrInvalid
	}
	for i, ref := range refs {
		if ref.Kind != kinds[i] || !digestValid(ref.ID) {
			return ErrInvalid
		}
	}
	if !validPosition(position) {
		return ErrInvalid
	}
	switch resource {
	case p.AddressHistory:
		if position.Kind == WalletSource {
			return nil
		}
	case p.Transactions:
		if position.Kind == HistorySource {
			return nil
		}
	case p.ActivityLogs:
		if position.Kind == ActivitySource {
			return nil
		}
	}
	return ErrInvalid
}

// SealRetained keeps the original dd1 size ceilings and key rotation. A
// separate authenticated domain prevents either codec from accepting the other.
func (c *Cursor) SealRetained(plan SourcePlan, b CursorBinding, resource p.Resource, basis RetainedBasis, set Digest, refs []SourceRef, position Position, until time.Time) (string, error) {
	if c == nil || c.keys[c.active] == nil || !digestValid(set) || until.Unix() < 0 || until.Unix() > p.MaxUnixSeconds || retainedCursorSelection(plan, resource, basis, refs, position) != nil {
		return "", ErrInvalid
	}
	binding, err := retainedBindingDigest(plan, b, resource)
	if err != nil {
		return "", err
	}
	pos, err := positionWire(position)
	if err != nil {
		return "", err
	}
	bind, _ := shortDigest(binding)
	sourceSet, _ := shortDigest(set)
	payload := retainedCursorPayload{V: 2, Binding: bind, Set: sourceSet, Refs: []cursorRef{}, Position: pos, Expires: strconv.FormatInt(until.Unix(), 10)}
	if basis.Valid() {
		copy := basis.Clone()
		payload.Basis = &copy
	}
	for _, ref := range refs {
		id, _ := shortDigest(ref.ID)
		payload.Refs = append(payload.Refs, cursorRef{kindCode(ref.Kind), id})
	}
	plain, err := jsonBytes(payload)
	if err != nil || len(plain) > 1408 {
		return "", ErrTooBroad
	}
	aead := c.keys[c.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	sealed := aead.Seal(nonce, nonce, plain, retainedCursorAAD(c.active))
	raw := "dd2." + c.active + "." + base64.RawURLEncoding.EncodeToString(sealed)
	if len(raw) > 2048 {
		return "", ErrTooBroad
	}
	return raw, nil
}

func (c *Cursor) OpenRetained(raw string, plan SourcePlan, b CursorBinding, resource p.Resource, now time.Time) (RetainedContinuation, error) {
	var out RetainedContinuation
	if c == nil || len(raw) > 2048 {
		return out, ErrInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "dd2" || !keyID(parts[1]) {
		return out, ErrInvalid
	}
	aead := c.keys[parts[1]]
	if aead == nil {
		return out, ErrInvalid
	}
	sealed, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || base64.RawURLEncoding.EncodeToString(sealed) != parts[2] || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return out, ErrInvalid
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], retainedCursorAAD(parts[1]))
	if err != nil || len(plain) > 1408 {
		return out, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.UseNumber()
	value, err := strictjson.ReadValue(decoder, 0, 12)
	if err != nil || hasNull(value) {
		return out, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return out, ErrInvalid
	}
	var payload retainedCursorPayload
	if strictjson.ExactDecodeWithOptions(value, &payload, strictjson.ShapeOptions{OptionalOmitEmpty: true}) != nil || payload.V != 2 || len(payload.Refs) < 1 || len(payload.Refs) > 5 {
		return out, ErrInvalid
	}
	expires, err := strconv.ParseInt(payload.Expires, 10, 64)
	if err != nil || strconv.FormatInt(expires, 10) != payload.Expires || expires <= now.Unix() || expires > p.MaxUnixSeconds {
		return out, ErrInvalid
	}
	expected, err := retainedBindingDigest(plan, b, resource)
	if err != nil {
		return out, err
	}
	actual, err := longDigest(payload.Binding)
	if err != nil {
		return out, err
	}
	if actual != expected {
		return out, ErrConflict
	}
	out.continuation.sourceSet, err = longDigest(payload.Set)
	if err != nil {
		return out, err
	}
	for _, ref := range payload.Refs {
		kind := codeKind(ref.Kind)
		id, err := longDigest(ref.ID)
		if err != nil || kind == "" {
			return RetainedContinuation{}, ErrInvalid
		}
		out.continuation.refs = append(out.continuation.refs, SourceRef{kind, id})
	}
	out.continuation.position, err = positionRead(payload.Position)
	if err != nil {
		return RetainedContinuation{}, err
	}
	if payload.Basis != nil {
		out.basis = payload.Basis.Clone()
	}
	if retainedCursorSelection(plan, resource, out.basis, out.continuation.refs, out.continuation.position) != nil {
		return RetainedContinuation{}, ErrInvalid
	}
	out.continuation.expires = expires
	return out, nil
}
