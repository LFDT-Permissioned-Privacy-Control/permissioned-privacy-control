package v2server

import (
	"encoding/json"
	"privacy-proxy/internal/operational/ssohttp"
)

// ssohttp.New performs the authoritative closed source/digest/key binding
// validation. This read only discovers approved key environment references.
func jsonDecodeRuntime(raw []byte, out *ssohttp.RuntimeSource) error { return json.Unmarshal(raw, out) }
