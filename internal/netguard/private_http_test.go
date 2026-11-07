package netguard

import (
	"net/netip"
	"testing"
)

func TestPrivateHTTPResolvedAddressRule(t *testing.T) {
	for _, row := range []struct {
		ip      string
		allowed bool
	}{{"127.0.0.1", true}, {"::1", true}, {"10.1.2.3", true}, {"100.64.1.2", true}, {"fc00::1", true}, {"::ffff:10.1.2.3", true}, {"8.8.8.8", false}, {"0.0.0.0", false}, {"::", false}, {"169.254.169.254", false}, {"fe80::1%en0", false}, {"::ffff:169.254.169.254", false}} {
		if got := CheckPrivateHTTPAddr(netip.MustParseAddr(row.ip)) == nil; got != row.allowed {
			t.Fatal(row.ip, got)
		}
	}
	if CheckPrivateHTTPAddr(netip.Addr{}) == nil {
		t.Fatal("invalid resolved address")
	}
}

func TestKnownIPv6MetadataAlwaysDeniedAfterNormalization(t *testing.T) {
	for _, raw := range []string{"fd00:ec2::254", "FD00:0EC2:0000:0000:0000:0000:0000:0254", "fd00:ec2::254%en0", "fd20:ce::254", "fd20:ce::254%en0"} {
		ip := netip.MustParseAddr(raw)
		for _, private := range []bool{false, true} {
			if CheckResolvedAddrForEnv(ip, private) == nil {
				t.Fatal("metadata address accepted", raw, private)
			}
		}
		if CheckPrivateHTTPAddr(ip) == nil {
			t.Fatal("cleartext metadata accepted", raw)
		}
		// Shared relaxed URL eligibility must agree with the resolved-address
		// deny, including ULA metadata that otherwise matches private ranges.
		urlHost := raw
		for i, c := range urlHost {
			if c == '%' {
				urlHost = urlHost[:i] + "%25" + urlHost[i+1:]
				break
			}
		}
		if ValidateWebhookURLForEnv("http://["+urlHost+"]/metadata", true) == nil {
			t.Fatal("shared metadata URL accepted", raw)
		}
		// Exercise the actual net.Dialer Control guard without opening a socket.
		for _, private := range []bool{false, true} {
			if guardDialControl(private)("tcp", "["+raw+"]:80", nil) == nil {
				t.Fatal("metadata dial accepted", raw, private)
			}
		}
	}
	if CheckResolvedAddrForEnv(netip.MustParseAddr("fd00:ec2::253"), true) != nil || CheckPrivateHTTPAddr(netip.MustParseAddr("fd20:ce::253")) != nil {
		t.Fatal("ordinary adjacent ULA rejected")
	}
}
