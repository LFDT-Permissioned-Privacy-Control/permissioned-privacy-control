package quotefeed

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"

	"privacy-proxy/internal/netguard"
)

func validateDestination(raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return ErrInvalid
	}
	// Apply the common literal-address deny before HTTP's private eligibility
	// branch; ULA also contains named IPv6 cloud metadata endpoints.
	if address, err := netip.ParseAddr(u.Hostname()); err == nil && netguard.CheckResolvedAddrForEnv(address, allowPrivate) != nil {
		return ErrInvalid
	}
	if u.Scheme == "http" {
		if !allowPrivate || netguard.ValidateWebhookURLForEnv(raw, true) != nil {
			return ErrInvalid
		}
		return nil
	}
	if u.Scheme != "https" {
		return ErrInvalid
	}
	if !allowPrivate && netguard.ValidateWebhookURLForEnv(raw, false) != nil {
		return ErrInvalid
	}
	return nil
}
func defaultTransport(raw string, allowPrivate bool) *http.Transport {
	t := netguard.GuardedTransport(allowPrivate)
	// A replaced global default must not silently bypass the guarded dial or
	// normal TLS verification. Explicit injected transports are trusted bindings.
	t.DialTLS = nil
	t.DialTLSContext = nil
	if t.TLSClientConfig != nil {
		t.TLSClientConfig = t.TLSClientConfig.Clone()
		t.TLSClientConfig.InsecureSkipVerify = false
	}
	u, _ := url.Parse(raw)
	if u.Scheme == "http" {
		dialer := netguard.GuardedDialer(true)
		guard := dialer.Control
		dialer.Control = func(network, address string, raw syscall.RawConn) error {
			if err := guard(network, address, raw); err != nil {
				return err
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return ErrInvalid
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return ErrInvalid
			}
			return netguard.CheckPrivateHTTPAddr(ip)
		}
		t.DialContext = dialer.DialContext
	}
	return t
}
