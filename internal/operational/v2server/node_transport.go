package v2server

import (
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"privacy-proxy/internal/rpcexecution"
)

const upstreamNodeCooldown = time.Second

var errNodeTransportUnavailable = errors.New("node transport unavailable")

type nodeCooldownState struct{ until time.Time }
type nodeCooldownEndpoint struct {
	headers map[string]bool
	states  map[[32]byte]*nodeCooldownState
}

// nodeTransport is shared only by owned node clients, including readiness and
// protected reads. Its registry is fixed from pinned startup configuration;
// incoming requests can neither add bindings nor select credentials. Aliases
// with the same URL and credential material deliberately share one cooldown.
// The composition root retains ownership of the underlying transport's close.
type nodeTransport struct {
	base      http.RoundTripper
	clock     func() time.Time
	endpoints map[string]*nodeCooldownEndpoint
	mu        sync.Mutex // protects cooldown timestamps only; never held over I/O
}

func nodeCooldownKey(endpoint, header, value string) [32]byte {
	return sha256.Sum256([]byte(endpoint + "\x00" + header + "\x00" + value))
}

func newNodeTransport(base http.RoundTripper, config Config, clock func() time.Time) (*nodeTransport, error) {
	if base == nil || clock == nil {
		return nil, ErrInvalid
	}
	t := &nodeTransport{base: base, clock: clock, endpoints: map[string]*nodeCooldownEndpoint{}}
	add := func(endpoint string, credential rpcexecution.Credential) error {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
			return ErrInvalid
		}
		header := http.CanonicalHeaderKey(credential.Header)
		if (header == "") != (credential.Value == "") || strings.ContainsAny(header+credential.Value, "\r\n\x00") {
			return ErrInvalid
		}
		endpoint = u.String() // the exact URL used by http.NewRequest, including query
		e := t.endpoints[endpoint]
		if e == nil {
			e = &nodeCooldownEndpoint{headers: map[string]bool{}, states: map[[32]byte]*nodeCooldownState{}}
			t.endpoints[endpoint] = e
		}
		if header != "" {
			e.headers[header] = true
		}
		key := nodeCooldownKey(endpoint, header, credential.Value)
		if e.states[key] == nil {
			e.states[key] = &nodeCooldownState{}
		}
		return nil
	}
	addEndpoint := func(endpoint Endpoint) error {
		cr, _, err := endpointCredential(endpoint.Credential)
		if err != nil {
			return err
		}
		return add(endpoint.URL, cr)
	}
	if err := addEndpoint(config.Data.DefaultNode); err != nil {
		return nil, err
	}
	for _, n := range config.Data.Nodes {
		if n.AllowUnauthenticated {
			if err := add(n.URL, rpcexecution.Credential{}); err != nil {
				return nil, err
			}
		}
		for _, credential := range n.Credentials {
			cr, _, err := endpointCredential(&credential)
			if err != nil {
				return nil, err
			}
			if err := add(n.URL, cr); err != nil {
				return nil, err
			}
		}
	}
	for _, n := range config.Protected.Nodes {
		if err := addEndpoint(n.Endpoint); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *nodeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	sent := false
	defer func() {
		// RoundTripper owns closing even a locally rejected request body. The
		// concrete RPC bodies are immutable in-memory bytes; never read them here.
		if !sent && request != nil && request.Body != nil {
			_ = request.Body.Close()
		}
	}()
	if request == nil || request.URL == nil || request.Context().Err() != nil {
		return nil, errNodeTransportUnavailable
	}
	endpoint := request.URL.String()
	e := t.endpoints[endpoint]
	if e == nil {
		return nil, errNodeTransportUnavailable
	}
	// Owned RPC clients set only Content-Type and their selected credential.
	// Reject unknown, duplicate or combined credentials instead of falling back
	// to an endpoint's unauthenticated binding. This is not authorization.
	var header, value string
	for name, values := range request.Header {
		name = http.CanonicalHeaderKey(name)
		if name == "Content-Type" {
			continue
		}
		if !e.headers[name] || header != "" || len(values) != 1 || values[0] == "" {
			return nil, errNodeTransportUnavailable
		}
		header, value = name, values[0]
	}
	state := e.states[nodeCooldownKey(endpoint, header, value)]
	if state == nil {
		return nil, errNodeTransportUnavailable
	}
	t.mu.Lock()
	blocked := t.clock().Before(state.until)
	t.mu.Unlock()
	if blocked {
		return nil, errNodeTransportUnavailable
	}
	sent = true
	response, err := t.base.RoundTrip(request)
	if response != nil && response.StatusCode == http.StatusTooManyRequests {
		t.mu.Lock()
		state.until = maxTime(state.until, t.clock().Add(upstreamNodeCooldown))
		t.mu.Unlock()
		if response.Body != nil {
			_ = response.Body.Close() // never read or relay a private upstream error
		}
		return nil, errNodeTransportUnavailable
	}
	// A late successful request must not erase a newer 429. There is no retry,
	// sleep, deadline replacement, body replay or early success reset.
	return response, err
}

func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}
