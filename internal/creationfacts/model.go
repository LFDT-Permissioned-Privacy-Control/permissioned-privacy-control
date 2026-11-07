// Package creationfacts contains detached operational creation metadata. It
// supplies no permission, ownership verdict, database or execution interpreter.
package creationfacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
)

const CaptureProfile = "same-node-caught-up/v1"
const CaughtUpAssertion = "operator-managed-canonical-head/v1"
const MaxSources = 64
const MaxCoverageBytes = 2048
const CaptureTimeout = 2 * time.Second
const HeartbeatTTL = 5 * time.Second

type Limits struct{ Headers, Births, Associations, CoverageRows, CoverageBytes, RevokedEpochs int64 }

func DefaultLimits() Limits { return Limits{10000000, 2000000, 8000000, 1600000, 3276800000, 1600000} }
func (l Limits) Valid() bool {
	m := DefaultLimits()
	return l.Headers > 0 && l.Headers <= m.Headers && l.Births > 0 && l.Births <= m.Births && l.Associations > 0 && l.Associations <= m.Associations && l.CoverageRows > 0 && l.CoverageRows <= m.CoverageRows && l.CoverageBytes > 0 && l.CoverageBytes <= m.CoverageBytes && l.RevokedEpochs > 0 && l.RevokedEpochs <= m.RevokedEpochs
}

var ErrInvalid = errors.New("invalid creation observation metadata")

type Digest [32]byte

func (d Digest) String() string               { return "sha256:" + hex.EncodeToString(d[:]) }
func (d Digest) MarshalText() ([]byte, error) { return []byte(d.String()), nil }
func (d *Digest) UnmarshalText(raw []byte) error {
	if len(raw) != 71 || !bytes.HasPrefix(raw, []byte("sha256:")) {
		return ErrInvalid
	}
	b, err := hex.DecodeString(string(raw[7:]))
	if err != nil || hex.EncodeToString(b) != string(raw[7:]) {
		return ErrInvalid
	}
	copy(d[:], b)
	return nil
}
func Hash(domain string, raw []byte) Digest {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(raw)
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}
func UUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func Text(raw string, max int, empty bool) bool {
	if (!empty && raw == "") || len(raw) > max || !utf8.ValidString(raw) {
		return false
	}
	for _, r := range raw {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// Network receives the exact already-derived ops-ledger-network identity from
// trusted startup assembly. Admission independently compares the complete tuple
// and Key against its one existing canonical NetworkBinding.Key implementation.
type Network struct {
	Key         Digest      `json:"key"`
	Environment string      `json:"environment"`
	ChainID     string      `json:"chainId"`
	Genesis     common.Hash `json:"genesis"`
	Deployment  string      `json:"deployment"`
}

func (n Network) Valid() bool {
	chain, err := strconv.ParseUint(n.ChainID, 10, 64)
	return n.Key != (Digest{}) && err == nil && chain > 0 && strconv.FormatUint(chain, 10) == n.ChainID && n.Genesis != (common.Hash{}) && Text(n.Environment, 128, false) && Text(n.Deployment, 128, false)
}

type State struct {
	Generation string
	Coverage   Digest
}

func (s State) Valid() bool { return UUID(s.Generation) }

// Source contains credential references and header names, never credential
// values. Equality describes the selected audited startup binding.
type Source struct {
	Network          Network `json:"network"`
	Organization     string  `json:"organization"`
	URL              string  `json:"url"`
	CredentialRef    string  `json:"credentialRef"`
	CredentialHeader string  `json:"credentialHeader"`
	Profile          string  `json:"profile"`
	PragueStart      uint64  `json:"pragueStart"`
	PragueEnd        uint64  `json:"pragueEnd"`
}

func (s Source) Valid() bool {
	u, err := url.Parse(s.URL)
	organizationOK := UUID(s.Organization) || (s.Profile == "reth-prague-included-creations/v1" && s.Organization == "")
	if !s.Network.Valid() || !organizationOK || len(s.URL) > 8192 || err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || s.PragueEnd <= s.PragueStart || !Text(s.CredentialRef, 256, true) {
		return false
	}
	if (s.CredentialRef == "") != (s.CredentialHeader == "") {
		return false
	}
	if s.CredentialHeader != "" {
		if len(s.CredentialHeader) > 256 {
			return false
		}
		for _, r := range s.CredentialHeader {
			if r <= 32 || r >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
				return false
			}
		}
	}
	return s.Profile == "geth-prague-lifecycle-signed/v1" || s.Profile == "geth-prague-lifecycle-guard/v1" || s.Profile == "reth-prague-included-creations/v1"
}
func (s Source) Digest() Digest {
	if !s.Valid() {
		return Digest{}
	}
	raw, _ := json.Marshal(s)
	return Hash("ops-creation-source/v1", raw)
}
func SourceSet(sources []Source) (Digest, error) {
	if len(sources) > MaxSources {
		return Digest{}, ErrInvalid
	}
	digests := make([]Digest, len(sources))
	for i, s := range sources {
		digests[i] = s.Digest()
		if digests[i] == (Digest{}) {
			return Digest{}, ErrInvalid
		}
	}
	slices.SortFunc(digests, func(a, b Digest) int { return bytes.Compare(a[:], b[:]) })
	raw := make([]byte, 0, 32*len(digests))
	for i, d := range digests {
		if i > 0 && d == digests[i-1] {
			return Digest{}, ErrInvalid
		}
		raw = append(raw, d[:]...)
	}
	return Hash("ops-creation-source-set/v1", raw), nil
}
func CaptureFence(network Digest) int64 {
	d := Hash("ops-creation-capture-fence/v1", network[:])
	return int64(binary.BigEndian.Uint64(d[:8]) | uint64(1)<<63)
}

type Header struct {
	Number       uint64
	Hash, Parent common.Hash
	Timestamp    uint64
}

func (h Header) Valid() bool { return h.Number <= math.MaxInt64 && h.Hash != (common.Hash{}) }

// Checkpoint is trusted store output, not a caller's readiness assertion. TTL
// belongs only to the live capture gate; it is not a historical expiry.
type Checkpoint struct {
	Network                     Digest
	State                       State
	ObserverEpoch, CaptureEpoch string
	SourceSet, Reference        Digest
	HighWater                   Header
	HeaderVersion, LeaseFence   int64
	RemainingTTL                time.Duration
}

func (c Checkpoint) Valid() bool {
	return c.Network != (Digest{}) && c.State.Valid() && UUID(c.ObserverEpoch) && UUID(c.CaptureEpoch) && c.SourceSet != (Digest{}) && c.Reference != (Digest{}) && c.HighWater.Valid() && c.HeaderVersion > 0 && c.LeaseFence > 0 && c.RemainingTTL > 0 && c.RemainingTTL <= HeartbeatTTL
}
func (c Checkpoint) SameTrust(other Checkpoint) bool {
	return c.Network == other.Network && c.State == other.State && c.ObserverEpoch == other.ObserverEpoch && c.CaptureEpoch == other.CaptureEpoch && c.SourceSet == other.SourceSet && c.Reference == other.Reference
}

// CoverageRecord is the bounded first observation persisted with a NEW seed.
// Its clocks/heartbeat/epochs are excluded from semantic seed identity.
type CoverageRecord struct {
	Version                                 int    `json:"v"`
	Policy                                  string `json:"p"`
	Network                                 Digest `json:"n"`
	State                                   State  `json:"s"`
	ObserverEpoch                           string `json:"o"`
	CaptureEpoch                            string `json:"c"`
	SourceSet                               Digest `json:"x"`
	Reference                               Digest `json:"r"`
	Ingress                                 Digest `json:"i"`
	HighWater                               Header `json:"h"`
	Latest                                  Header `json:"l"`
	HeaderVersion                           int64  `json:"b"`
	LeaseFence                              int64  `json:"f"`
	ProbeStarted, ProbeFinished, ValidUntil time.Time
}

func (r CoverageRecord) Canonical() ([]byte, error) {
	if r.Version != 1 || r.Policy != CaptureProfile || r.Network == (Digest{}) || !r.State.Valid() || !UUID(r.ObserverEpoch) || !UUID(r.CaptureEpoch) || r.SourceSet == (Digest{}) || r.Reference == (Digest{}) || r.Ingress == (Digest{}) || !r.HighWater.Valid() || !r.Latest.Valid() || r.Latest.Number < r.HighWater.Number || r.HeaderVersion < 1 || r.LeaseFence < 1 || r.ProbeStarted.Unix() < 0 || r.ProbeFinished.Before(r.ProbeStarted) || r.ProbeFinished.Sub(r.ProbeStarted) > CaptureTimeout || r.ProbeFinished.Unix() > 253402300799 || r.ValidUntil.Unix() > 253402300799 || r.ValidUntil.Before(r.ProbeFinished) || r.ValidUntil.Sub(r.ProbeFinished) > HeartbeatTTL {
		return nil, ErrInvalid
	}
	// PostgreSQL timestamptz has microsecond precision. One canonical form
	// prevents the first persisted observation changing digest on readback.
	r.ProbeStarted, r.ProbeFinished, r.ValidUntil = r.ProbeStarted.UTC().Truncate(time.Microsecond), r.ProbeFinished.UTC().Truncate(time.Microsecond), r.ValidUntil.UTC().Truncate(time.Microsecond)
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxCoverageBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
func (r CoverageRecord) Digest() Digest {
	raw, err := r.Canonical()
	if err != nil {
		return Digest{}
	}
	return Hash("ops-creation-capture-record/v1", raw)
}
