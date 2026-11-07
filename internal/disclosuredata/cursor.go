package disclosuredata

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/strictjson"
)

type Cursor struct {
	active string
	keys   map[string]cipher.AEAD
}
type Continuation struct {
	refs      []SourceRef
	position  Position
	sourceSet Digest
	expires   int64
}

func (c Continuation) References() []SourceRef { return append([]SourceRef{}, c.refs...) }
func (c Continuation) Position() Position      { return *ClonePosition(&c.position) }
func (c Continuation) VerifySourceSet(d Digest) error {
	if !digestValid(d) || d != c.sourceSet {
		return ErrConflict
	}
	return nil
}
func NewCursor(k Keys) (*Cursor, error) {
	keys, e := cloneKeys(k)
	if e != nil {
		return nil, e
	}
	out := &Cursor{active: keys.Active.ID, keys: map[string]cipher.AEAD{}}
	all := []Key{keys.Active}
	if keys.Previous != nil {
		all = append(all, *keys.Previous)
	}
	for _, key := range all {
		block, e := aes.NewCipher(key.Bytes)
		if e != nil {
			return nil, ErrInvalid
		}
		a, e := cipher.NewGCM(block)
		if e != nil {
			return nil, ErrInvalid
		}
		out.keys[key.ID] = a
	}
	return out, nil
}
func bindingDigest(b CursorBinding) (Digest, error) {
	if !digestValid(b.Namespace) || !uuidValid(b.CaseID) || b.CaseVersion < 1 || !actor(b.RecipientActorID) || !digestValid(b.BundleDigest) || !digestValid(b.RuleDigest) || !digestValid(b.QueryDigest) || !digestValid(b.SourcePlanDigest) || !digestValid(b.RenderGeneration) {
		return "", ErrInvalid
	}
	return hashParts("ops.disclosure.cursor-binding/v1", []byte(b.Namespace), []byte(b.CaseID), []byte(strconv.FormatInt(b.CaseVersion, 10)), []byte(b.RecipientActorID), []byte(b.BundleDigest), []byte(b.RuleDigest), []byte(b.QueryDigest), []byte(b.SourcePlanDigest), []byte(b.RenderGeneration)), nil
}
func shortDigest(d Digest) (string, error) {
	raw, e := digestBytes(d)
	if e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func longDigest(s string) (Digest, error) {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != s {
		return "", ErrInvalid
	}
	return Digest("sha256:" + hex.EncodeToString(b)), nil
}
func kindCode(k SourceKind) string {
	switch k {
	case ActivitySource:
		return "a"
	case FinanceSource:
		return "f"
	case HistorySource:
		return "h"
	case SanctionsSource:
		return "s"
	case WalletSource:
		return "w"
	}
	return ""
}
func codeKind(s string) SourceKind {
	switch s {
	case "a":
		return ActivitySource
	case "f":
		return FinanceSource
	case "h":
		return HistorySource
	case "s":
		return SanctionsSource
	case "w":
		return WalletSource
	}
	return ""
}

type cursorRef struct {
	Kind string `json:"k"`
	ID   string `json:"id"`
}
type cursorPosition struct {
	Kind     string  `json:"k"`
	Time     *string `json:"t,omitempty"`
	Producer *string `json:"p,omitempty"`
	Run      *string `json:"r,omitempty"`
	Ordinal  *string `json:"o,omitempty"`
	Record   *string `json:"id,omitempty"`
	Block    *string `json:"n,omitempty"`
	Index    *uint32 `json:"i,omitempty"`
	Hash     *string `json:"h,omitempty"`
	Address  *string `json:"a,omitempty"`
}
type cursorPayload struct {
	V        uint8          `json:"v"`
	Binding  string         `json:"b"`
	Set      string         `json:"s"`
	Refs     []cursorRef    `json:"r"`
	Position cursorPosition `json:"p"`
	Expires  string         `json:"exp"`
}

func ptr[T any](v T) *T { return &v }
func positionWire(p Position) (cursorPosition, error) {
	out := cursorPosition{Kind: kindCode(p.Kind)}
	if !validPosition(p) {
		return out, ErrInvalid
	}
	switch p.Kind {
	case ActivitySource:
		x := p.Activity
		out.Time = ptr(strconv.FormatInt(x.ObservedAtMicros, 10))
		out.Producer = &x.ProducerID
		out.Run = &x.RunID
		out.Ordinal = ptr(string(x.CompletionOrdinal))
		out.Record = &x.RecordID
	case HistorySource:
		x := p.Transaction
		out.Block = ptr(string(x.BlockNumber))
		out.Index = &x.TransactionIndex
		out.Hash = ptr(base64.RawURLEncoding.EncodeToString(x.Hash[:]))
	case WalletSource:
		out.Address = ptr(base64.RawURLEncoding.EncodeToString(p.Address.Address[:]))
	}
	return out, nil
}
func positionRead(w cursorPosition) (Position, error) {
	out := Position{Kind: codeKind(w.Kind)}
	used := 0
	for _, v := range []*string{w.Time, w.Producer, w.Run, w.Ordinal, w.Record, w.Block, w.Hash, w.Address} {
		if v != nil {
			used++
		}
	}
	if w.Index != nil {
		used++
	}
	switch out.Kind {
	case ActivitySource:
		if used != 5 || w.Time == nil || w.Producer == nil || w.Run == nil || w.Ordinal == nil || w.Record == nil {
			return out, ErrInvalid
		}
		t, e := strconv.ParseInt(*w.Time, 10, 64)
		if e != nil || strconv.FormatInt(t, 10) != *w.Time {
			return out, ErrInvalid
		}
		out.Activity = &ActivityPosition{t, *w.Producer, *w.Run, Count(*w.Ordinal), *w.Record}
	case HistorySource:
		if used != 3 || w.Block == nil || w.Index == nil || w.Hash == nil {
			return out, ErrInvalid
		}
		b, e := base64.RawURLEncoding.DecodeString(*w.Hash)
		if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != *w.Hash {
			return out, ErrInvalid
		}
		x := TransactionPosition{BlockNumber: Count(*w.Block), TransactionIndex: *w.Index}
		copy(x.Hash[:], b)
		out.Transaction = &x
	case WalletSource:
		if used != 1 || w.Address == nil {
			return out, ErrInvalid
		}
		b, e := base64.RawURLEncoding.DecodeString(*w.Address)
		if e != nil || len(b) != 20 || base64.RawURLEncoding.EncodeToString(b) != *w.Address {
			return out, ErrInvalid
		}
		x := AddressPosition{}
		copy(x.Address[:], b)
		out.Address = &x
	default:
		return out, ErrInvalid
	}
	if !validPosition(out) {
		return out, ErrInvalid
	}
	return out, nil
}
func cursorAAD(id string) []byte {
	return framed([]byte("ops.disclosure.data-cursor/v1"), []byte("dd1"), []byte(id))
}
func (c *Cursor) Seal(b CursorBinding, set Digest, refs []SourceRef, pos Position, until time.Time) (string, error) {
	if c == nil || c.keys[c.active] == nil {
		return "", ErrInvalid
	}
	bind, e := bindingDigest(b)
	if e != nil || !digestValid(set) || len(refs) < 1 || len(refs) > 5 || until.Unix() < 0 || until.Unix() > p.MaxUnixSeconds {
		return "", ErrInvalid
	}
	w, e := positionWire(pos)
	if e != nil {
		return "", e
	}
	bs, _ := shortDigest(bind)
	ss, _ := shortDigest(set)
	payload := cursorPayload{1, bs, ss, []cursorRef{}, w, strconv.FormatInt(until.Unix(), 10)}
	for i, r := range refs {
		if kindCode(r.Kind) == "" || !digestValid(r.ID) || i > 0 && refs[i-1].Kind >= r.Kind {
			return "", ErrInvalid
		}
		id, _ := shortDigest(r.ID)
		payload.Refs = append(payload.Refs, cursorRef{kindCode(r.Kind), id})
	}
	raw, e := jsonBytes(payload)
	if e != nil || len(raw) > 1408 {
		return "", ErrTooBroad
	}
	a := c.keys[c.active]
	nonce := make([]byte, a.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return "", ErrUnavailable
	}
	sealed := a.Seal(nonce, nonce, raw, cursorAAD(c.active))
	out := "dd1." + c.active + "." + base64.RawURLEncoding.EncodeToString(sealed)
	if len(out) > 2048 {
		return "", ErrTooBroad
	}
	return out, nil
}
func (c *Cursor) Open(raw string, b CursorBinding, now time.Time) (Continuation, error) {
	var out Continuation
	if c == nil || len(raw) > 2048 {
		return out, ErrInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "dd1" || !keyID(parts[1]) {
		return out, ErrInvalid
	}
	a := c.keys[parts[1]]
	if a == nil {
		return out, ErrInvalid
	}
	sealed, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || base64.RawURLEncoding.EncodeToString(sealed) != parts[2] || len(sealed) < a.NonceSize()+a.Overhead() {
		return out, ErrInvalid
	}
	plain, e := a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], cursorAAD(parts[1]))
	if e != nil || len(plain) > 1408 {
		return out, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.UseNumber()
	value, e := strictjson.ReadValue(dec, 0, 8)
	if e != nil || hasNull(value) {
		return out, ErrInvalid
	}
	if _, e = dec.Token(); e != io.EOF {
		return out, ErrInvalid
	}
	var payload cursorPayload
	if strictjson.ExactDecodeWithOptions(value, &payload, strictjson.ShapeOptions{OptionalOmitEmpty: true}) != nil || payload.V != 1 || len(payload.Refs) < 1 || len(payload.Refs) > 5 {
		return out, ErrInvalid
	}
	expiry, e := strconv.ParseInt(payload.Expires, 10, 64)
	if e != nil || strconv.FormatInt(expiry, 10) != payload.Expires || expiry <= now.Unix() || expiry > p.MaxUnixSeconds {
		return out, ErrInvalid
	}
	expected, e := bindingDigest(b)
	if e != nil {
		return out, e
	}
	got, e := longDigest(payload.Binding)
	if e != nil {
		return out, e
	}
	if got != expected {
		return out, ErrConflict
	}
	set, e := longDigest(payload.Set)
	if e != nil {
		return out, e
	}
	for i, r := range payload.Refs {
		k := codeKind(r.Kind)
		id, e := longDigest(r.ID)
		if e != nil || k == "" || i > 0 && out.refs[i-1].Kind >= k {
			return out, ErrInvalid
		}
		out.refs = append(out.refs, SourceRef{k, id})
	}
	pos, e := positionRead(payload.Position)
	if e != nil {
		return out, e
	}
	out.position = pos
	out.sourceSet = set
	out.expires = expiry
	return out, nil
}
