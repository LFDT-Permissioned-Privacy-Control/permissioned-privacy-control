// Package ssosql stores structurally bounded SSO flows. It does not authenticate
// users, decrypt tokens or authorize a grant. App/retention credentials are part
// of the metadata/counter integrity and availability trust boundary.
package ssosql

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	m "privacy-proxy/internal/ssotransaction"
	"sync/atomic"
	"time"
)

var ErrInvalid = m.ErrInvalid
var ErrNotFound = errors.New("SSO record not found")
var ErrConflict = errors.New("SSO storage conflict")
var ErrExpired = errors.New("SSO flow expired")
var ErrCapacity = errors.New("SSO storage capacity exceeded")
var ErrUnavailable = errors.New("SSO storage unavailable")
var ErrRole = errors.New("SSO storage role denied")

type Roles struct{ App, Retention string }
type Registration struct {
	Namespace, BrokerNamespace m.Digest
	Epoch, BrokerRecoveryEpoch string
	Limits                     m.Limits
	Roles                      Roles
}

func (r Registration) scope() m.Scope {
	return m.Scope{Namespace: r.Namespace, Epoch: r.Epoch, BrokerNamespace: r.BrokerNamespace, BrokerRecoveryEpoch: r.BrokerRecoveryEpoch}
}

type Metadata struct {
	Scope          m.Scope
	Limits         m.Limits
	Roles          Roles
	SchemaVersion  uint8
	SchemaChecksum string
}
type Usage struct{ ActiveRows, ReadyRows, ActiveCipherBytes, AllRows, MetadataBytes int64 }
type StatusResult struct {
	Metadata Metadata
	Ready    bool
	Usage    Usage
}
type Config struct {
	DSN      string
	Expected m.Scope
	Clock    func() time.Time
}
type Store struct {
	pool     *pgxpool.Pool
	metadata Metadata
	clock    func() time.Time
	mode     string
	closed   atomic.Bool
}

func (s *Store) Metadata() Metadata {
	if s == nil {
		return Metadata{}
	}
	return s.metadata
}

// AppMetadata checks only this concrete pointer's local app-role/lifetime
// binding. Every operation still independently checks live SQL readiness,
// catalog, ACL and recovery scope; this method is not a database health check.
func (s *Store) AppMetadata() (Metadata, error) {
	if !s.valid("app") {
		return Metadata{}, ErrRole
	}
	return s.metadata, nil
}
func (s *Store) Close() {
	if s != nil && s.pool != nil && s.closed.CompareAndSwap(false, true) {
		s.pool.Close()
	}
}

type Receipt struct {
	owner     *Store
	capture   m.Capture
	operation string
}

func (r Receipt) ID() string         { return r.capture.ID }
func (r Receipt) Capture() m.Capture { return r.capture }

// CommitGate is a trusted, bounded LOCAL context/clock/result-expiry check.
// It must do no SQL, network, provider operation or human interaction.
type CommitGate func() error
type CleanupCounts struct{ DeletedPending, ExpiredReady, DeletedAudit int64 }

func (s *Store) now() (m.Micros, error) {
	if s == nil || s.clock == nil || s.closed.Load() {
		return 0, ErrUnavailable
	}
	t := s.clock().UTC()
	if t.Before(time.Unix(0, 0)) || t.After(time.Unix(253402300799, 999999999)) {
		return 0, ErrUnavailable
	}
	v := m.Micros(t.UnixMicro())
	if !v.Valid() {
		return 0, ErrUnavailable
	}
	return v, nil
}
func (s *Store) valid(mode string) bool {
	return s != nil && s.pool != nil && !s.closed.Load() && s.mode == mode
}
func gateNow(ctx context.Context, g CommitGate) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if g != nil {
		return g()
	}
	return nil
}
func usageValid(u Usage, l m.Limits) bool {
	return l.Valid() && u.ActiveRows >= 0 && u.ReadyRows >= 0 && u.AllRows >= 0 && u.ActiveCipherBytes >= 0 && u.ReadyRows <= u.ActiveRows && u.ActiveRows <= u.AllRows && u.ActiveRows <= l.ActiveRows && u.ReadyRows <= l.ReadyRows && u.AllRows <= l.AllRows && u.ActiveCipherBytes <= l.ActiveCipherBytes && u.MetadataBytes == u.AllRows*m.MetadataChargeBytes && u.MetadataBytes <= l.MetadataBytes && (u.ActiveRows == 0) == (u.ActiveCipherBytes == 0) && u.ActiveCipherBytes >= 28*u.ActiveRows+28*u.ReadyRows
}
