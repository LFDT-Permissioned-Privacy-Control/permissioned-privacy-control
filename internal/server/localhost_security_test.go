package server

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

// TestLocalhostIPRangeVulnerability tests for the overly broad IP range check
// in the localhost-only middleware.
//
// VULNERABILITY: The code uses strings.HasPrefix(clientIP, "172.") which matches
// 172.0.0.0/8 (entire class B range) instead of just Docker's 172.16.0.0/12.
func TestLocalhostIPRangeVulnerability(t *testing.T) {
	// Simulate the current (vulnerable) localhost check
	isAllowedVulnerable := func(clientIP string) bool {
		return clientIP == "127.0.0.1" ||
			clientIP == "::1" ||
			strings.HasPrefix(clientIP, "172.") || // VULNERABILITY: Too broad
			strings.HasPrefix(clientIP, "192.168.") ||
			strings.HasPrefix(clientIP, "100.")
	}

	// Proper CIDR-based check
	isAllowedSecure := func(clientIP string) bool {
		if clientIP == "127.0.0.1" || clientIP == "::1" {
			return true
		}

		ip := net.ParseIP(clientIP)
		if ip == nil {
			return false
		}

		// Docker bridge networks: 172.16.0.0/12
		_, dockerNet, _ := net.ParseCIDR("172.16.0.0/12")
		if dockerNet.Contains(ip) {
			return true
		}

		// Private networks: 192.168.0.0/16
		_, privateNet, _ := net.ParseCIDR("192.168.0.0/16")
		if privateNet.Contains(ip) {
			return true
		}

		// Tailscale CGNAT: 100.64.0.0/10
		_, tailscaleNet, _ := net.ParseCIDR("100.64.0.0/10")
		if tailscaleNet.Contains(ip) {
			return true
		}

		return false
	}

	testCases := []struct {
		ip                   string
		expectedVulnerable   bool
		expectedSecure       bool
		isVulnerabilityProof bool
		description          string
	}{
		// Legitimate localhost
		{"127.0.0.1", true, true, false, "IPv4 localhost"},
		{"::1", true, true, false, "IPv6 localhost"},

		// Legitimate Docker networks (172.16.0.0/12)
		{"172.16.0.1", true, true, false, "Docker network start"},
		{"172.17.0.1", true, true, false, "Default Docker bridge gateway"},
		{"172.31.255.254", true, true, false, "Docker network end"},

		// VULNERABILITY: IPs outside Docker range but matching prefix
		{"172.0.0.1", true, false, true, "VULN: Outside Docker range (172.0.x.x)"},
		{"172.1.0.1", true, false, true, "VULN: Outside Docker range (172.1.x.x)"},
		{"172.15.255.255", true, false, true, "VULN: Just below Docker range"},
		{"172.32.0.1", true, false, true, "VULN: Above Docker range (172.32.x.x)"},
		{"172.100.0.1", true, false, true, "VULN: Far above Docker range"},
		{"172.255.255.255", true, false, true, "VULN: Max in 172.x range"},

		// Private networks (should be allowed)
		{"192.168.0.1", true, true, false, "Private network (home)"},
		{"192.168.1.100", true, true, false, "Private network (common)"},

		// Tailscale CGNAT (100.64.0.0/10)
		{"100.64.0.1", true, true, false, "Tailscale CGNAT start"},
		{"100.127.255.254", true, true, false, "Tailscale CGNAT end"},

		// Tailscale IPs outside CGNAT range (but still allowed by prefix check)
		{"100.0.0.1", true, false, true, "VULN: Outside Tailscale range (100.0.x.x)"},
		{"100.63.255.255", true, false, true, "VULN: Just below Tailscale CGNAT"},
		{"100.128.0.1", true, false, true, "VULN: Above Tailscale CGNAT"},

		// Public IPs (should be blocked)
		{"8.8.8.8", false, false, false, "Google DNS (public)"},
		{"1.1.1.1", false, false, false, "Cloudflare DNS (public)"},
		{"203.0.113.1", false, false, false, "TEST-NET-3 (documentation range)"},
	}

	vulnerabilitiesFound := 0

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			vulnResult := isAllowedVulnerable(tc.ip)
			secureResult := isAllowedSecure(tc.ip)

			if vulnResult != tc.expectedVulnerable {
				t.Errorf("Vulnerable check for %s: got %v, want %v",
					tc.ip, vulnResult, tc.expectedVulnerable)
			}

			if secureResult != tc.expectedSecure {
				t.Errorf("Secure check for %s: got %v, want %v",
					tc.ip, secureResult, tc.expectedSecure)
			}

			// Flag vulnerabilities
			if tc.isVulnerabilityProof && vulnResult && !secureResult {
				vulnerabilitiesFound++
				t.Logf("SECURITY FINDING: IP %s would be allowed by vulnerable check but blocked by secure check",
					tc.ip)
			}
		})
	}

	t.Logf("Total IP range vulnerabilities found: %d", vulnerabilitiesFound)
	if vulnerabilitiesFound > 0 {
		t.Logf("RECOMMENDATION: Replace strings.HasPrefix checks with proper CIDR parsing")
	}
}

// TestBatchRequestBlockingSecurity verifies batch requests are blocked
func TestBatchRequestBlockingSecurity(t *testing.T) {
	// Simple batch detection (starts with '[' after trimming whitespace)
	isBatchRequest := func(body []byte) bool {
		trimmed := bytes.TrimSpace(body)
		return len(trimmed) > 0 && trimmed[0] == '['
	}

	testCases := []struct {
		name    string
		body    []byte
		isBatch bool
	}{
		{
			name:    "Single request",
			body:    []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`),
			isBatch: false,
		},
		{
			name:    "Batch request (array)",
			body:    []byte(`[{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}]`),
			isBatch: true,
		},
		{
			name:    "Batch request (multiple)",
			body:    []byte(`[{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2}]`),
			isBatch: true,
		},
		{
			name:    "Whitespace before array",
			body:    []byte(`  [{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}]`),
			isBatch: true,
		},
		{
			name:    "Newline before array",
			body:    []byte("\n[{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}]"),
			isBatch: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isBatch := isBatchRequest(tc.body)
			if isBatch != tc.isBatch {
				t.Errorf("IsBatchRequest(%s) = %v, want %v", tc.name, isBatch, tc.isBatch)
			}
		})
	}
}

// TestMethodBlockingCaseSensitivitySecurity tests method blocking case handling
func TestMethodBlockingCaseSensitivitySecurity(t *testing.T) {
	// The actual blocked methods map (from rbac/access.go)
	blockedMap := map[string]bool{
		"debug_traceTransaction": true,
		"admin_peers":            true,
		"personal_sign":          true,
	}

	// Helper that mimics the current blocking logic
	isBlocked := func(method string) bool {
		if blockedMap[method] {
			return true
		}

		// Prefix check (case-sensitive)
		prefixes := []string{"debug_", "admin_", "personal_"}
		for _, prefix := range prefixes {
			if strings.HasPrefix(method, prefix) {
				return true
			}
		}
		return false
	}

	testCases := []struct {
		method   string
		expected bool
	}{
		// Standard blocked methods
		{"debug_traceTransaction", true},
		{"admin_peers", true},
		{"personal_sign", true},

		// Case variations - documenting current behavior
		{"DEBUG_traceTransaction", false}, // Currently NOT blocked (case mismatch)
		{"Admin_peers", false},            // Currently NOT blocked
		{"PERSONAL_sign", false},          // Currently NOT blocked

		// Prefix matches
		{"debug_newMethod", true},
		{"admin_newMethod", true},
		{"personal_newMethod", true},

		// Case variations on prefix - documenting behavior
		{"Debug_newMethod", false}, // NOT blocked (prefix case mismatch)
		{"ADMIN_newMethod", false}, // NOT blocked
	}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			blocked := isBlocked(tc.method)
			if blocked != tc.expected {
				t.Logf("Method %s: blocked=%v (expected=%v)", tc.method, blocked, tc.expected)
			}

			// Flag case-sensitivity issues
			if strings.ToLower(tc.method) != tc.method && !blocked {
				lower := strings.ToLower(tc.method)
				if isBlocked(lower) {
					t.Logf("NOTE: Lowercase %s IS blocked but %s is NOT (case-sensitive)", lower, tc.method)
				}
			}
		})
	}
}
