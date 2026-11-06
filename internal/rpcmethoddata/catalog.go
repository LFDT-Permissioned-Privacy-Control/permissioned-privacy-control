package rpcmethoddata

import (
	"maps"
	"slices"
	"sort"
)

const Version = "rpc-method-catalog/v1"

// Catalog contains trusted compiled method data, not operation-handler support.
type Catalog struct {
	Version        string
	Assignable     []string
	Aliases        map[string]string
	Wildcard       []string
	RequiredClaims map[string]string
}

// No built-in method currently requires an allowlist-level operational claim.
// Operation-specific deploy/upgrade checks are separate from name membership.
var requiredClaims = map[string]string{}

func ReadSet() map[string]bool         { return maps.Clone(readMethods) }
func WriteSet() map[string]bool        { return maps.Clone(writeMethods) }
func TraceSet() map[string]bool        { return maps.Clone(traceMethods) }
func ExactOnly() []string              { return slices.Clone(exactOnlyMethods) }
func BlockedSet() map[string]bool      { return maps.Clone(blockedMethods) }
func BlockedPrefixes() []string        { return slices.Clone(blockedPrefixes) }
func BlockExemptions() map[string]bool { return maps.Clone(blockExemptions) }
func RequiredClaim(name string) string { return requiredClaims[name] }

func IsBlocked(name string) bool {
	return BlockedWith(name, blockedMethods, blockedPrefixes, blockExemptions)
}

// BuiltinCatalog returns fresh copies. Legacy namespace registration, exported
// map mutations and caller mutation cannot change this versioned snapshot.
func BuiltinCatalog() Catalog {
	all, wildcard := map[string]bool{}, map[string]bool{}
	for _, set := range []map[string]bool{readMethods, writeMethods, traceMethods} {
		for name := range set {
			if !IsBlocked(name) {
				all[name], wildcard[name] = true, true
			}
		}
	}
	for _, name := range exactOnlyMethods {
		if !IsBlocked(name) {
			all[name] = true
		}
	}
	return Catalog{Version: Version, Assignable: names(all), Aliases: map[string]string{}, Wildcard: names(wildcard), RequiredClaims: maps.Clone(requiredClaims)}
}

func names(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
