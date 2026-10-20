package rbac

import "testing"

// RD-1180: CanonicalizeMethod normalizes mixed-case built-in method names to
// their canonical camelCase spelling so internal dispatch / target-selector
// extraction / RBAC gates can't be skipped by casing. Unknown methods pass
// through unchanged (fail closed downstream).
func TestCanonicalizeMethod(t *testing.T) {
	cases := []struct{ in, want string }{
		// Security-critical dispatch methods.
		{"eth_SENDRawTransaction", "eth_sendRawTransaction"},
		{"ETH_SENDRAWTRANSACTION", "eth_sendRawTransaction"},
		{"debug_TRACETRANSACTION", "debug_traceTransaction"},
		{"DEBUG_TRACECALL", "debug_traceCall"},
		// Target/selector extraction methods.
		{"eth_CALL", "eth_call"},
		{"ETH_GETLOGS", "eth_getLogs"},
		{"eth_getbalance", "eth_getBalance"},
		// Per-address-gated read-ops not in Read/Write/Trace, added explicitly
		// (Copilot review): a mixed-case form would otherwise skip target extraction.
		{"eth_GETPROOF", "eth_getProof"},
		{"ETH_CREATEACCESSLIST", "eth_createAccessList"},
		// Already-canonical stays canonical.
		{"eth_sendRawTransaction", "eth_sendRawTransaction"},
		{"eth_call", "eth_call"},
		{"eth_getTransactionReceipt", "eth_getTransactionReceipt"},
		// Unknown / operator / wildcard methods pass through UNCHANGED.
		{"linea_estimateGas", "linea_estimateGas"},
		{"linea_ESTIMATEGAS", "linea_ESTIMATEGAS"},
		{"totally_unknown_method", "totally_unknown_method"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := CanonicalizeMethod(tc.in); got != tc.want {
			t.Errorf("CanonicalizeMethod(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The canonical index must never map two distinct built-in methods to the same
// lowercase key (which would make canonicalization ambiguous).
func TestCanonicalizeMethod_NoCaseCollisions(t *testing.T) {
	seen := map[string]string{}
	for _, set := range []map[string]bool{ReadMethods, WriteMethods, TraceMethods} {
		for name := range set {
			lower := ""
			for _, r := range name {
				if r >= 'A' && r <= 'Z' {
					r += 'a' - 'A'
				}
				lower += string(r)
			}
			if prev, ok := seen[lower]; ok && prev != name {
				t.Fatalf("case collision: %q and %q share lowercase %q", prev, name, lower)
			}
			seen[lower] = name
		}
	}
}
