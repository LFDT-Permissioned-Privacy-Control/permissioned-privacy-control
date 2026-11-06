package policycore

import "sort"

// Native evaluation and optional code generation use the same rule order.
func sortedFrameKeys(index map[frameKey][]*compiledRule) []frameKey {
	keys := make([]frameKey, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.targetClass != b.targetClass {
			return a.targetClass < b.targetClass
		}
		if a.storage != b.storage {
			return a.storage.Hex() < b.storage.Hex()
		}
		if a.code != b.code {
			return a.code.Hex() < b.code.Hex()
		}
		if a.selectorMode != b.selectorMode {
			return a.selectorMode < b.selectorMode
		}
		return string(a.selector[:]) < string(b.selector[:])
	})
	return keys
}
