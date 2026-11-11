package proxy

import "privacy-proxy/internal/rpcenvelope"

// Envelope and errors retain the existing public parser API and error identity.
type Envelope = rpcenvelope.Envelope

var ErrAmbiguousRequest = rpcenvelope.ErrAmbiguousRequest
var ErrBatchRequest = rpcenvelope.ErrBatchRequest

func ParseEnvelope(body []byte) (*Envelope, error) { return rpcenvelope.ParseEnvelope(body) }
func CheckDecodedRequest(method string, params []interface{}) (*Envelope, error) {
	return rpcenvelope.CheckDecodedRequest(method, params)
}
func IsBatchRequest(body []byte) bool                         { return rpcenvelope.IsBatchRequest(body) }
func ParseMethod(body []byte) (string, error)                 { return rpcenvelope.ParseMethod(body) }
func ParseRequest(body []byte) (string, []interface{}, error) { return rpcenvelope.ParseRequest(body) }
