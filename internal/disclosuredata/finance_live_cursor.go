package disclosuredata

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/strictjson"
)

// LiveFinanceRead is only a closed wire/source-profile selection. It grants no
// case, principal or source authority.
func LiveFinanceRead(plan SourcePlan, q NormalizedQuery) bool {
	return NativeFinancePlan(plan) && q.Resource() == p.ComplianceReport && q.View() == List
}

// FinanceLiveIdentity deliberately excludes page rows/counts/observation time.
// Each live page is a separate RR observation of the same selected source.
func FinanceLiveIdentity(plan SourcePlan, descriptor SourceDescriptor) (Digest, error) {
	if !NativeFinancePlan(plan) || descriptor.Kind != FinanceSource || descriptor.FormatDigest != FinanceLiveFormat() {
		return "", ErrInvalid
	}
	if _, err := SourceReferencesRetained(plan, []SourceDescriptor{descriptor}); err != nil {
		return "", err
	}
	return hashParts("ops.disclosure.finance-live-source/v1", []byte(plan.NetworkKey), []byte(descriptor.Epoch), []byte(descriptor.Generation), []byte(plan.PlanDigest), []byte(descriptor.FormatDigest), []byte(descriptor.CoverageDigest)), nil
}

type FinanceLiveContinuation struct {
	identity Digest
	position Position
}

func (c FinanceLiveContinuation) SourceIdentity() Digest { return c.identity }
func (c FinanceLiveContinuation) Position() Position     { return *ClonePosition(&c.position) }

type financeLiveCursorPayload struct {
	Version  uint8  `json:"v"`
	Binding  string `json:"b"`
	Identity string `json:"s"`
	Time     string `json:"t"`
	ID       Count  `json:"i"`
	Expires  string `json:"exp"`
}

func financeLiveAAD(id string) []byte {
	return framed([]byte("ops.disclosure.finance-live-cursor/v1"), []byte("df1"), []byte(id))
}

func (c *Cursor) SealLiveFinance(plan SourcePlan, binding CursorBinding, identity Digest, position Position, until time.Time) (string, error) {
	if c == nil || c.keys[c.active] == nil || !NativeFinancePlan(plan) || !ValidRetainedPlan(plan) || binding.BundleDigest != plan.BundleDigest || binding.SourcePlanDigest != plan.PlanDigest || !digestValid(identity) || !validPosition(position) || position.Kind != FinanceSource || position.FinanceLive == nil || until.Unix() < 0 || until.Unix() > p.MaxUnixSeconds {
		return "", ErrInvalid
	}
	digest, err := bindingDigest(binding)
	if err != nil {
		return "", err
	}
	bind, _ := shortDigest(digest)
	source, _ := shortDigest(identity)
	plain, err := jsonBytes(financeLiveCursorPayload{1, bind, source, strconv.FormatInt(position.FinanceLive.ObservedAtMicros, 10), position.FinanceLive.ID, strconv.FormatInt(until.Unix(), 10)})
	if err != nil || len(plain) > 1408 {
		return "", ErrTooBroad
	}
	aead := c.keys[c.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	return "df1." + c.active + "." + base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, financeLiveAAD(c.active))), nil
}

func (c *Cursor) OpenLiveFinance(raw string, plan SourcePlan, binding CursorBinding, now time.Time) (FinanceLiveContinuation, error) {
	var out FinanceLiveContinuation
	if c == nil || len(raw) > 2048 || !NativeFinancePlan(plan) || !ValidRetainedPlan(plan) || binding.BundleDigest != plan.BundleDigest || binding.SourcePlanDigest != plan.PlanDigest {
		return out, ErrInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "df1" || !keyID(parts[1]) || c.keys[parts[1]] == nil {
		return out, ErrInvalid
	}
	aead := c.keys[parts[1]]
	sealed, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || base64.RawURLEncoding.EncodeToString(sealed) != parts[2] || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return out, ErrInvalid
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], financeLiveAAD(parts[1]))
	if err != nil || len(plain) > 1408 {
		return out, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.UseNumber()
	value, err := strictjson.ReadValue(decoder, 0, 4)
	if err != nil {
		return out, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return out, ErrInvalid
	}
	var payload financeLiveCursorPayload
	if strictjson.ExactDecode(value, &payload) != nil || payload.Version != 1 {
		return out, ErrInvalid
	}
	expires, err := strconv.ParseInt(payload.Expires, 10, 64)
	if err != nil || strconv.FormatInt(expires, 10) != payload.Expires || expires <= now.Unix() || expires > now.Add(300*time.Second).Unix() {
		return out, ErrInvalid
	}
	expected, err := bindingDigest(binding)
	if err != nil {
		return out, err
	}
	got, err := longDigest(payload.Binding)
	if err != nil || got != expected {
		return out, ErrConflict
	}
	out.identity, err = longDigest(payload.Identity)
	if err != nil {
		return out, err
	}
	micros, err := strconv.ParseInt(payload.Time, 10, 64)
	if err != nil || strconv.FormatInt(micros, 10) != payload.Time {
		return FinanceLiveContinuation{}, ErrInvalid
	}
	out.position = Position{Kind: FinanceSource, FinanceLive: &FinanceLivePosition{ObservedAtMicros: micros, ID: payload.ID}}
	if !validPosition(out.position) {
		return FinanceLiveContinuation{}, ErrInvalid
	}
	return out, nil
}
