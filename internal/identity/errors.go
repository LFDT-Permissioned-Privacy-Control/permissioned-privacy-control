package identity

type Error struct {
	Code  string
	Field string
}

func (e *Error) Error() string         { return "identity: " + e.Code + " (" + e.Field + ")" }
func invalid(code, field string) error { return &Error{Code: code, Field: field} }
