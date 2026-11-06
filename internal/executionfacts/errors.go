package executionfacts

import "fmt"

type ErrorCode string

const (
	InvalidOptions ErrorCode = "invalid_options"
	InvalidTrace   ErrorCode = "invalid_trace"
	RootMismatch   ErrorCode = "root_mismatch"
	LimitExceeded  ErrorCode = "limit_exceeded"
)

// Error identifies a bounded failure without echoing confidential node data.
type Error struct {
	Code   ErrorCode
	Record int
	Field  string
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("execution evidence %s at record %d field %s: %s", e.Code, e.Record, e.Field, e.Reason)
}

func fail(code ErrorCode, record int, field, reason string) error {
	return &Error{code, record, field, reason}
}
