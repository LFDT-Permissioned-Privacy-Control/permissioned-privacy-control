package activitylog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/netip"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/strictjson"
)

// Record is a validated detached spool variant. It has no sequence field.
type Record struct {
	fields spool
	valid  bool
}

// spool deliberately lists nineteen fields rather than making b optional.
type spool struct {
	Version        uint8  `json:"v"`
	Kind           uint8  `json:"k"`
	Network        string `json:"n"`
	Generation     string `json:"g"`
	Configuration  string `json:"x"`
	ProducerID     string `json:"p"`
	RunID          string `json:"r"`
	RecordID       string `json:"q"`
	Ordinal        string `json:"o"`
	ObservedMicros int64  `json:"t"`
	ActorID        string `json:"a"`
	DataOrg        string `json:"d"`
	Policy         string `json:"z"`
	Method         string `json:"m"`
	IP             string `json:"i"`
	HTTP           uint16 `json:"h"`
	RPCError       *int32 `json:"e"`
	Outcome        string `json:"u"`
	Status         uint16 `json:"s"`
}

func CanonicalUUID(v string) bool {
	id, err := uuid.Parse(v)
	return err == nil && id != uuid.Nil && id.String() == v
}
func ParseDigestHex(v string) (Digest, error) {
	var d Digest
	if len(v) != 64 {
		return d, ErrInvalid
	}
	b, err := hex.DecodeString(v)
	if err != nil || hex.EncodeToString(b) != v {
		return d, ErrInvalid
	}
	copy(d[:], b)
	return d, nil
}
func positive(v string) (uint64, bool) {
	if len(v) < 1 || len(v) > 19 || v[0] == '0' {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 63)
	return n, err == nil && n > 0 && strconv.FormatUint(n, 10) == v
}
func ValidMethod(v string) bool {
	if len(v) < 1 || len(v) > 100 {
		return false
	}
	for i, b := range []byte(v) {
		letter := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
		if !letter && (i == 0 || !(b >= '0' && b <= '9' || b == '_' || b == '.')) {
			return false
		}
	}
	return true
}
func status(o string) uint16 {
	switch Outcome(o) {
	case Success:
		return 200
	case Invalid:
		return 400
	case Unauthenticated:
		return 401
	case Denied:
		return 403
	case EvaluationFailed:
		return 422
	case Unavailable:
		return 503
	case Unconfirmed:
		return 502
	}
	return 0
}
func validEnvelope(e Envelope, sealed bool) bool {
	if e.Version != 1 || e.Kind != 1 || !CanonicalUUID(e.Generation) || !CanonicalUUID(e.ProducerID) || !CanonicalUUID(e.RunID) || !CanonicalUUID(e.RecordID) || e.ObservedMicros < 0 || e.ObservedMicros > MaxObservedMicros || !ValidMethod(e.Method) || e.HTTP < 100 || e.HTTP > 599 || status(e.Outcome) == 0 || status(e.Outcome) != e.Status {
		return false
	}
	if _, err := ParseDigestHex(e.Network); err != nil {
		return false
	}
	if _, err := ParseDigestHex(e.Configuration); err != nil {
		return false
	}
	if _, ok := positive(e.Ordinal); !ok {
		return false
	}
	if sealed {
		if _, ok := positive(e.BufferSeq); !ok {
			return false
		}
	} else if e.BufferSeq != "" {
		return false
	}
	if e.ActorID != "" && !identity.ValidActorID(e.ActorID) {
		return false
	}
	if e.DataOrg != "" {
		if e.ActorID == "" || !CanonicalUUID(e.DataOrg) {
			return false
		}
		if d, err := ParseDigestHex(e.Policy); err != nil || d == (Digest{}) {
			return false
		}
	} else if e.Policy != "" {
		return false
	}
	if len(e.IP) > 45 {
		return false
	}
	if e.IP != "" {
		ip, err := netip.ParseAddr(e.IP)
		if err != nil || ip.Zone() != "" || ip.String() != e.IP {
			return false
		}
	}
	return e.Outcome != string(Success) || e.RPCError == nil && e.HTTP >= 200 && e.HTTP <= 299
}
func detachError(e *int32) *int32 {
	if e == nil {
		return nil
	}
	v := *e
	return &v
}
func (r Record) Fields() Envelope {
	s := r.fields
	return Envelope{s.Version, s.Kind, s.Network, s.Generation, s.Configuration, s.ProducerID, s.RunID, s.RecordID, s.Ordinal, s.ObservedMicros, s.ActorID, s.DataOrg, s.Policy, s.Method, s.IP, s.HTTP, detachError(s.RPCError), s.Outcome, s.Status, ""}
}
func toRecord(e Envelope) Record {
	return Record{fields: spool{e.Version, e.Kind, e.Network, e.Generation, e.Configuration, e.ProducerID, e.RunID, e.RecordID, e.Ordinal, e.ObservedMicros, e.ActorID, e.DataOrg, e.Policy, e.Method, e.IP, e.HTTP, detachError(e.RPCError), e.Outcome, e.Status}, valid: true}
}
func EncodeSpool(r Record) ([]byte, error) {
	if !r.valid || !validEnvelope(r.Fields(), false) {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(r.fields)
	if err != nil || len(raw) > MaxEncodedBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
func exact(raw []byte, out any) error {
	if len(raw) < 1 || len(raw) > MaxEncodedBytes || !utf8.Valid(raw) {
		return ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := strictjson.ReadValue(dec, 0, 4)
	if err != nil {
		return ErrInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalid
	}
	// The shared exact-shape decoder deliberately forbids all nulls. This
	// closed wire has precisely one nullable scalar, e. Validate its required
	// presence/type using a numeric placeholder, then restore ONLY that field.
	m, ok := v.(map[string]any)
	if !ok {
		return ErrInvalid
	}
	errorValue, present := m["e"]
	nullable := present && errorValue == nil
	if nullable {
		m["e"] = json.Number("0")
	}
	if strictjson.ExactDecode(v, out) != nil {
		return ErrInvalid
	}
	if nullable {
		switch x := out.(type) {
		case *spool:
			x.RPCError = nil
		case *Envelope:
			x.RPCError = nil
		default:
			return ErrInvalid
		}
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, encoded) {
		return ErrInvalid
	}
	return nil
}
func DecodeSpool(raw []byte) (Record, error) {
	var s spool
	if exact(raw, &s) != nil {
		return Record{}, ErrInvalid
	}
	r := Record{fields: s, valid: true}
	if !validEnvelope(r.Fields(), false) {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func SealEnvelope(r Record, seq uint64) ([]byte, error) {
	if !r.valid || seq == 0 || seq > math.MaxInt64 {
		return nil, ErrInvalid
	}
	e := r.Fields()
	e.BufferSeq = strconv.FormatUint(seq, 10)
	if !validEnvelope(e, true) {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > MaxEncodedBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

// DecodeEnvelope validates the exact canonical sealed representation; its
// returned fields describe metadata, not an identity or approval capability.
func DecodeEnvelope(raw []byte) (Envelope, error) {
	var e Envelope
	if exact(raw, &e) != nil || !validEnvelope(e, true) {
		return Envelope{}, ErrInvalid
	}
	return e, nil
}
