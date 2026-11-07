// Package chainlock supplies the unchanged access-log advisory lock identity.
package chainlock

import "hash/fnv"

// Key is the original class730076/FNV32 key, independent of DB/verifier code.
func Key(chainName string) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(chainName))
	return int64(730076)<<32 | int64(h.Sum32())
}
