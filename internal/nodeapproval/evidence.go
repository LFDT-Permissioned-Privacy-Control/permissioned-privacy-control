package nodeapproval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

const RetainedGuardProfile = "geth-prague-guard-retained/v1"
const MaxRetainedMuxBytes = 32 << 20
const MaxRetainedPartBytes = 16 << 20

// Optional inspection never changes the legacy header decode outcome. Bound
// the NEW retained copy before allocation; repeats invalidate evidence only.
type optionalHeaderQuantity struct {
	seen, invalid bool
	raw           json.RawMessage
}

func (q *optionalHeaderQuantity) UnmarshalJSON(raw []byte) error {
	if q.seen {
		q.invalid = true
		q.raw = nil
		return nil
	}
	q.seen = true
	if len(raw) < 5 || len(raw) > 20 {
		q.invalid = true
		return nil
	}
	if _, ok := retainedQuantity(raw); !ok {
		q.invalid = true
		return nil
	}
	q.raw = bytes.Clone(raw)
	return nil
}
func (q optionalHeaderQuantity) bytes() json.RawMessage {
	if !q.seen || q.invalid {
		return nil
	}
	return q.raw
}

// PreparedEvidence is request-local, immutable original preflight evidence.
// It is not an approval authority or a proof that a transaction was published.
type PreparedEvidence struct{ data *preparedEvidence }
type preparedEvidence struct {
	origin            *Service
	prepared          *Prepared
	approval          Approval
	header            common.Hash
	number, timestamp uint64
	calls, prestate   []byte
}

func (e PreparedEvidence) Calls() []byte {
	if e.data == nil {
		return nil
	}
	return bytes.Clone(e.data.calls)
}
func (e PreparedEvidence) Prestate() []byte {
	if e.data == nil {
		return nil
	}
	return bytes.Clone(e.data.prestate)
}
func (e PreparedEvidence) HeaderHash() common.Hash {
	if e.data == nil {
		return common.Hash{}
	}
	return e.data.header
}
func (e PreparedEvidence) HeaderNumber() uint64 {
	if e.data == nil {
		return 0
	}
	return e.data.number
}
func (e PreparedEvidence) HeaderTimestamp() uint64 {
	if e.data == nil {
		return 0
	}
	return e.data.timestamp
}
func (e PreparedEvidence) Profile() string {
	if e.data == nil {
		return ""
	}
	return RetainedGuardProfile
}
func (e PreparedEvidence) HashMode() uint8 {
	if e.data == nil {
		return 0
	}
	return e.data.approval.HashMode
}
func (e PreparedEvidence) ChainID() uint64 {
	if e.data == nil {
		return 0
	}
	return e.data.approval.ChainID
}
func (e PreparedEvidence) TransactionHash() common.Hash {
	if e.data == nil {
		return common.Hash{}
	}
	return e.data.approval.TxHash
}
func (e PreparedEvidence) Fingerprint() common.Hash {
	if e.data == nil {
		return common.Hash{}
	}
	return e.data.approval.Fingerprint
}

func (p *Prepared) Evidence() (PreparedEvidence, bool) {
	if p == nil || p.evidence == nil {
		return PreparedEvidence{}, false
	}
	return PreparedEvidence{p.evidence}, true
}

// EvidenceFor additionally proves this exact service produced the retained
// snapshot and its exported compatibility approval has not been substituted.
func (s *Service) EvidenceFor(p *Prepared) (PreparedEvidence, bool) {
	if s == nil || p == nil || p.evidence == nil || p.evidence.origin != s || p.evidence.prepared != p {
		return PreparedEvidence{}, false
	}
	a, b := p.Approval, p.evidence.approval
	if a.HashMode != b.HashMode || a.ChainID != b.ChainID || a.TxHash != b.TxHash || a.Fingerprint != b.Fingerprint || a.Principal != b.Principal || a.Signature != b.Signature {
		return PreparedEvidence{}, false
	}
	return p.Evidence()
}

func retainedQuantity(raw json.RawMessage) (uint64, bool) {
	if len(raw) < 5 || len(raw) > 20 {
		return 0, false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) < 3 || len(s) > 18 || !strings.HasPrefix(s, "0x") || (len(s) > 3 && s[2] == '0') {
		return 0, false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s[2:], 16, 64)
	return n, err == nil
}

func retainPreparedEvidence(origin *Service, a Approval, mux []byte, header common.Hash, number, timestamp json.RawMessage) *preparedEvidence {
	// Bound NEW retention work before RawMessage decoding/copying. Legacy
	// acquisition and fingerprint behavior deliberately remain unchanged.
	if len(mux) > MaxRetainedMuxBytes || header == (common.Hash{}) {
		return nil
	}
	n, nok := retainedQuantity(number)
	t, tok := retainedQuantity(timestamp)
	if !nok || !tok {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(mux))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return nil
	}
	parts := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil
		}
		name, ok := key.(string)
		if !ok || (name != "callTracer" && name != "prestateTracer") || parts[name] != nil {
			return nil
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil || len(raw) > MaxRetainedPartBytes {
			return nil
		}
		parts[name] = raw
	}
	if _, err = d.Token(); err != nil {
		return nil
	}
	if _, err = d.Token(); err != io.EOF {
		return nil
	}
	if len(parts) != 2 || len(parts["callTracer"]) == 0 || len(parts["prestateTracer"]) == 0 {
		return nil
	}
	return &preparedEvidence{origin: origin, approval: a, header: header, number: n, timestamp: t, calls: parts["callTracer"], prestate: parts["prestateTracer"]}
}

// BoundPreflightOptions are trusted startup inputs. This service has no
// signer, delivery lane or queue and never reads node-kind/hash-mode env vars.
type BoundPreflightOptions struct {
	URL                               string
	CredentialHeader, CredentialValue string
	Transport                         http.RoundTripper
	HashMode                          uint8
}

func NewBoundPreflight(o BoundPreflightOptions) (*Service, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || o.Transport == nil || !validHashMode(o.HashMode) || (o.CredentialHeader == "") != (o.CredentialValue == "") || len(o.CredentialHeader) > 128 || len(o.CredentialValue) > 8192 || strings.ContainsAny(o.CredentialValue, "\r\n\x00") {
		return nil, errors.New("invalid bound preflight configuration")
	}
	for _, c := range o.CredentialHeader {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return nil, errors.New("invalid bound preflight configuration")
		}
	}
	h := &http.Client{Transport: o.Transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	options := []rpc.ClientOption{rpc.WithHTTPClient(h)}
	if o.CredentialHeader != "" {
		options = append(options, rpc.WithHeader(o.CredentialHeader, o.CredentialValue))
	}
	client, err := rpc.DialOptions(context.Background(), o.URL, options...)
	if err != nil {
		return nil, errors.New("bound preflight unavailable")
	}
	return &Service{hashMode: o.HashMode, rpc: client, rpcHTTP: h}, nil
}
