// Package nodehttp builds the HTTP client the proxy and tracer use to talk to
// the single upstream Ethereum node.
//
// Both the forwarder (internal/proxy) and the tracer (internal/tracer) talk to
// ONE node host at high request rates. Go's http.DefaultTransport caps idle
// keep-alive connections at MaxIdleConnsPerHost=2, so under concurrency nearly
// every request past the second opens and then discards a fresh TCP connection
// — churn, TIME_WAIT accumulation, and ephemeral-port pressure (RD-1112). This
// package centralises a transport tuned for the single-upstream, high-fanout
// shape, with the pool sizes configurable so operators can match their node.
package nodehttp

import (
	"net"
	"net/http"
	"time"
)

// TransportConfig tunes the connection pool for the upstream node client.
// Zero values fall back to DefaultTransportConfig in NewClient.
type TransportConfig struct {
	// MaxIdleConns bounds idle keep-alive connections across all hosts.
	MaxIdleConns int
	// MaxIdleConnsPerHost is the load-bearing knob: idle keep-alive
	// connections retained for the single node host. Go's default is 2.
	MaxIdleConnsPerHost int
	// MaxConnsPerHost caps total (active+idle) connections to the node host.
	// 0 means unlimited — appropriate when the node, not the proxy, is the
	// throughput governor.
	MaxConnsPerHost int
	// IdleConnTimeout is how long an idle keep-alive connection is retained.
	IdleConnTimeout time.Duration
}

// DefaultTransportConfig returns pool sizes tuned for forwarding to a single
// node host under high concurrency. These are deliberately generous on idle
// reuse (the thing the Go default gets wrong for this workload) while leaving
// total connections to the node unbounded by default.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 256,
		MaxConnsPerHost:     0, // unlimited; the node is the governor
		IdleConnTimeout:     90 * time.Second,
	}
}

// withDefaults fills zero fields from DefaultTransportConfig so partial
// (env-derived) configs still produce a sane transport.
func (c TransportConfig) withDefaults() TransportConfig {
	d := DefaultTransportConfig()
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = d.MaxIdleConns
	}
	if c.MaxIdleConnsPerHost == 0 {
		c.MaxIdleConnsPerHost = d.MaxIdleConnsPerHost
	}
	// MaxConnsPerHost==0 is a legitimate value (unlimited), so it is left as-is.
	if c.IdleConnTimeout == 0 {
		c.IdleConnTimeout = d.IdleConnTimeout
	}
	return c
}

// NewTransport builds a tuned *http.Transport for the upstream node.
func NewTransport(cfg TransportConfig) *http.Transport {
	cfg = cfg.withDefaults()
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewClient builds an *http.Client with the given request timeout and a tuned
// upstream transport.
func NewClient(timeout time.Duration, cfg TransportConfig) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewTransport(cfg),
	}
}
