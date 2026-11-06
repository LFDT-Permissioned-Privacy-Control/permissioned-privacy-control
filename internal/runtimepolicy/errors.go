package runtimepolicy

type ErrorCode string

const (
	InvalidSnapshot     ErrorCode = "snapshot"
	InvalidAccess       ErrorCode = "access"
	Expired             ErrorCode = "expired"
	AmbiguousCredential ErrorCode = "ambiguous-credential"
)

type Error struct{ Code ErrorCode }

func (e *Error) Error() string { return "runtimepolicy: " + string(e.Code) }
