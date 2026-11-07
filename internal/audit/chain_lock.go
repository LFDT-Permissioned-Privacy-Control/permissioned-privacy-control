package audit

import "privacy-proxy/internal/audit/chainlock"

// AccessLogChainLockKey preserves the original per-chain advisory lock bytes.
func AccessLogChainLockKey(chainName string) int64 { return chainlock.Key(chainName) }
