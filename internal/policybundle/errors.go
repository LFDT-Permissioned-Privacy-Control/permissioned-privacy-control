package policybundle

import "strings"

type ErrorCode string

const (
	InvalidSelection   ErrorCode = "selection"
	InvalidSchema      ErrorCode = "schema"
	IntegrityFailure   ErrorCode = "integrity"
	ReferenceFailure   ErrorCode = "reference"
	UnsupportedFeature ErrorCode = "unsupported"
	CapabilityMismatch ErrorCode = "capabilities"
	LimitExceeded      ErrorCode = "limit"
	ReadFailure        ErrorCode = "read"
	Canceled           ErrorCode = "canceled"
)

// Error is a bounded diagnostic. It never embeds OS paths, source bytes or
// secret values. Kind, organization and field identify the rejected source.
type Error struct {
	Code           ErrorCode
	Kind           Kind
	OrganizationID string
	Field          string
	message        string
	cause          error
}

func (e *Error) Error() string {
	return "policybundle: " + string(e.Code) + " " + bounded(string(e.Kind), 32) + " " + bounded(e.OrganizationID, 36) + " " + bounded(e.Field, 128) + ": " + bounded(e.message, 256)
}

func (e *Error) Unwrap() error { return e.cause }

func bounded(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '?'
		}
		return r
	}, s)
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}

func fail(code ErrorCode, kind Kind, org, field, message string) error {
	return &Error{Code: code, Kind: kind, OrganizationID: org, Field: field, message: message}
}
