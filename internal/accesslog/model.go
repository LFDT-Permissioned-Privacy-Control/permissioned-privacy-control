// Package accesslog serves bounded own-organization investigations of the
// committed sealed request population. It owns no store or identity directory.
package accesslog

import (
	"context"
	"errors"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/identity"
)

var (
	ErrInvalid      = errors.New("invalid access log query")
	ErrUnauthorized = errors.New("invalid or expired access")
	ErrForbidden    = errors.New("organization log access forbidden")
	ErrCursor       = errors.New("cursor context mismatch")
	ErrExpired      = errors.New("cursor expired")
	ErrUnavailable  = errors.New("activity source unavailable")
)

type RetentionError struct{ FromMicros int64 }

func (*RetentionError) Error() string { return "requested history was pruned" }

type Query struct {
	ActorID, Method, Outcome, RequestReference string
	FromMicros, ToMicros                       int64
	Limit                                      int
}

func (q Query) Valid() bool {
	return (q.ActorID == "" || identity.ValidActorID(q.ActorID)) && (q.Method == "" || a.ValidMethod(q.Method) && activitymethoddata.Classify(q.Method) != activitymethoddata.Unknown) && ValidOutcome(q.Outcome) && (q.RequestReference == "" || a.CanonicalUUID(q.RequestReference)) && q.FromMicros >= 0 && q.ToMicros > q.FromMicros && q.ToMicros <= a.MaxObservedMicros+1 && q.Limit >= 1 && q.Limit <= 100
}
func ValidOutcome(v string) bool {
	switch v {
	case "", string(a.Success), string(a.Invalid), string(a.Unauthenticated), string(a.Denied), string(a.EvaluationFailed), string(a.Unavailable), string(a.Unconfirmed):
		return true
	}
	return false
}

type Position struct {
	ObservedMicros    int64
	ProducerID, RunID string
	Ordinal           int64
	RecordID          string
}

func (p Position) Valid(q Query) bool {
	return p.ObservedMicros >= q.FromMicros && p.ObservedMicros < q.ToMicros && a.CanonicalUUID(p.ProducerID) && a.CanonicalUUID(p.RunID) && a.CanonicalUUID(p.RecordID) && p.Ordinal > 0
}

type Cut struct {
	Metadata                        a.StoreMetadata
	Reference, Coverage, Population string
	RetainedFromMicros              int64
	AsOfMicros                      int64
}
type Snapshot interface {
	Cut() Cut
	ReadOrgPage(context.Context, string, Query, *Position) ([]a.Envelope, bool, error)
	Close()
	CheckCurrent(context.Context) error
}
type Reader interface {
	OpenAdmin(context.Context, string, int64) (Snapshot, error)
}
type Item struct {
	RequestReference    string  `json:"requestReference"`
	ObservedAt          string  `json:"observedAt"`
	ActorID             string  `json:"actorId"`
	OrganizationID      string  `json:"organizationId"`
	Method              string  `json:"method"`
	Outcome             string  `json:"outcome"`
	HTTPStatus          uint16  `json:"httpStatus"`
	RPCErrorCode        *int32  `json:"rpcErrorCode"`
	RecordedStatus      uint16  `json:"recordedStatus"`
	PolicyDigest        *string `json:"policyDigest"`
	ConfigurationDigest string  `json:"configurationDigest"`
	Reason              string  `json:"reason"`
	TrustedIP           *string `json:"trustedIP"`
}
type Source struct {
	SourceID            string `json:"sourceId"`
	Generation          string `json:"generation"`
	NetworkDigest       string `json:"networkDigest"`
	ConfigurationDigest string `json:"configurationDigest"`
	HeadReference       string `json:"headReference"`
	SourceAsOf          string `json:"sourceAsOf"`
	RetainedFrom        string `json:"retainedFrom"`
	Population          string `json:"population"`
	Coverage            string `json:"coverage"`
}
type Page struct {
	Items  []Item  `json:"items"`
	Next   *string `json:"next"`
	Source Source  `json:"source"`
}
