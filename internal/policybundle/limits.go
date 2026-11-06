package policybundle

import "math"

type Limits struct {
	MaxManifestBytes        int64
	MaxDocumentBytes        int64
	MaxBundleBytes          int64
	MaxDocuments            int
	MaxOrganizations        int
	MaxJSONDepth            int
	MaxGroupsPerOrg         int
	MaxContractsPerOrg      int
	MaxNativeRulesPerOrg    int
	MaxABIEntries           int
	MaxABITypeDepth         int
	MaxExpandedABIHeadSlots int
}

func DefaultLimits() Limits {
	return Limits{MaxManifestBytes: 1 << 20, MaxDocumentBytes: 1 << 20, MaxBundleBytes: 64 << 20, MaxDocuments: 1024, MaxOrganizations: 256, MaxJSONDepth: 64, MaxGroupsPerOrg: 4096, MaxContractsPerOrg: 4096, MaxNativeRulesPerOrg: 32768, MaxABIEntries: 4096, MaxABITypeDepth: 16, MaxExpandedABIHeadSlots: 4096}
}

func (l Limits) valid() bool {
	if l.MaxManifestBytes <= 0 || l.MaxDocumentBytes <= 0 || l.MaxBundleBytes <= 0 || l.MaxManifestBytes >= math.MaxInt64 || l.MaxDocumentBytes >= math.MaxInt64 || l.MaxBundleBytes >= math.MaxInt64 {
		return false
	}
	for _, n := range []int{l.MaxDocuments, l.MaxOrganizations, l.MaxJSONDepth, l.MaxGroupsPerOrg, l.MaxContractsPerOrg, l.MaxNativeRulesPerOrg, l.MaxABIEntries, l.MaxABITypeDepth, l.MaxExpandedABIHeadSlots} {
		if n <= 0 || n == math.MaxInt {
			return false
		}
	}
	return true
}
