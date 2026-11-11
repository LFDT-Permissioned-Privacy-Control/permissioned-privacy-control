package ssotransaction

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func frame(h hash.Hash, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// CaptureRecord is exact structural CAS framing, never a verified session.
func CaptureRecord(r Record) (Capture, error) {
	if ValidateRecord(r) != nil {
		return Capture{}, ErrInvalid
	}
	h := sha256.New()
	frame(h, []byte("ops.sso.storage-capture/v1"))
	put := func(b []byte) { frame(h, b) }
	text := func(s string) { put([]byte(s)) }
	integer := func(n int64) { text(strconv.FormatInt(n, 10)) }
	optional := func(b []byte) {
		if b == nil {
			put([]byte{0})
		} else {
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(b)+1))
			_, _ = h.Write(n[:])
			_, _ = h.Write([]byte{1})
			_, _ = h.Write(b)
		}
	}
	optText := func(s string) { optional([]byte(s)) }
	optInt := func(n int64) { optText(strconv.FormatInt(n, 10)) }
	p := r.Pending
	text(p.ID)
	put(p.Scope.Namespace[:])
	text(p.Scope.Epoch)
	put(p.Scope.BrokerNamespace[:])
	text(p.Scope.BrokerRecoveryEpoch)
	integer(int64(r.Phase))
	text(p.ClientID)
	put(p.ClientCatalogDigest[:])
	put(p.IdentityDigest[:])
	put(p.Recipient[:])
	put(p.StateHash[:])
	put(p.RedirectHash[:])
	put(p.PKCES256[:])
	text(p.ContextKeyID)
	optional(p.ContextCiphertext)
	integer(int64(p.CreatedAt))
	integer(int64(p.ExpiresAt))
	v := r.Ready
	if v == nil {
		for range 16 {
			optional(nil)
		}
	} else {
		optional(v.CodeHash[:])
		optInt(int64(v.CodeExpiresAt))
		optText(v.GrantKeyID)
		optional(v.GrantCiphertext)
		optText(v.ActorID)
		optText(v.ProfileID)
		optional(v.ProfileDigest[:])
		optText(v.FamilyID)
		optInt(v.FamilyGeneration)
		optional(v.FamilyHandleHash[:])
		optional(v.AccessDigest[:])
		optInt(int64(v.AccessExpiresAt))
		optInt(int64(v.FamilyExpiresAt))
		optInt(int64(v.PreparedAt))
		optional(v.CodeResponseDigest[:])
		optInt(int64(v.CodeResponseBytes))
	}
	if r.ConsumedAt == nil {
		optional(nil)
	} else {
		optInt(int64(*r.ConsumedAt))
	}
	if r.TokenResponse == nil {
		optional(nil)
		optional(nil)
	} else {
		optional(r.TokenResponse.Digest[:])
		optInt(int64(r.TokenResponse.Bytes))
	}
	if r.RetainUntil == nil {
		optional(nil)
	} else {
		optInt(int64(*r.RetainUntil))
	}
	var d Digest
	copy(d[:], h.Sum(nil))
	return Capture{p.ID, p.Scope, r.Phase, d}, nil
}
func NamespaceFor(broker Digest, origin string) (Digest, error) {
	if !broker.Valid() || len(origin) < 1 || len(origin) > 2048 {
		return Digest{}, ErrInvalid
	}
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.String() != origin || strings.ContainsAny(origin, "%\\ \t\r\n") || u.Host != strings.ToLower(u.Host) {
		return Digest{}, ErrInvalid
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.String() != host {
			return Digest{}, ErrInvalid
		}
	} else {
		labels := strings.Split(host, ".")
		last := labels[len(labels)-1]
		// Namespace origins must keep the same host in browser URL parsing;
		// numeric-ending names can instead become noncanonical IPv4 aliases.
		if len(host) > 253 || last == "" || strings.HasPrefix(last, "0x") {
			return Digest{}, ErrInvalid
		}
		numeric := true
		for _, b := range []byte(last) {
			numeric = numeric && b >= '0' && b <= '9'
		}
		if numeric {
			return Digest{}, ErrInvalid
		}
		for _, label := range labels {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Digest{}, ErrInvalid
			}
			for _, c := range []byte(label) {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return Digest{}, ErrInvalid
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return Digest{}, ErrInvalid
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return Digest{}, ErrInvalid
	}
	h := sha256.New()
	frame(h, []byte("ops.sso.namespace/v1"))
	frame(h, broker[:])
	frame(h, []byte(origin))
	var d Digest
	copy(d[:], h.Sum(nil))
	return d, nil
}
