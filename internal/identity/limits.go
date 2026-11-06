package identity

import "math"

// Limits are explicit engineering caps, not measured capacity promises.
type Limits struct {
	MaxCompactAccessBytes    int
	MaxDecodedHeaderBytes    int
	MaxDecodedPayloadBytes   int
	MaxTokenJSONDepth        int
	MaxFacts                 int
	MaxFactValueBytes        int
	MaxSourceSubjectBytes    int
	MaxProfileIDBytes        int
	MaxKidBytes              int
	MaxIdentityDocumentBytes int
	MaxCatalogJSONDepth      int
	MaxIssuers               int
	MaxKeysPerIssuer         int
	MaxTotalKeys             int
	MaxProfiles              int
	MaxMappings              int
	MaxTotalGroupReferences  int
	MaxGroupsPerMapping      int
	MaxURLBytes              int
	MaxSourceIDBytes         int
	MaxPredicateDecimalBytes int
}

func DefaultLimits() Limits {
	return Limits{
		MaxCompactAccessBytes: 16384, MaxDecodedHeaderBytes: 2048, MaxDecodedPayloadBytes: 12288,
		MaxTokenJSONDepth: 16, MaxFacts: 256, MaxFactValueBytes: 256, MaxSourceSubjectBytes: 1024,
		MaxProfileIDBytes: 128, MaxKidBytes: 128, MaxIdentityDocumentBytes: 1 << 20, MaxCatalogJSONDepth: 32,
		MaxIssuers: 16, MaxKeysPerIssuer: 16, MaxTotalKeys: 64, MaxProfiles: 256, MaxMappings: 8192,
		MaxTotalGroupReferences: 32768, MaxGroupsPerMapping: 4096, MaxURLBytes: 2048, MaxSourceIDBytes: 128,
		MaxPredicateDecimalBytes: 78,
	}
}

func (l Limits) Valid() bool {
	for _, n := range []int{l.MaxCompactAccessBytes, l.MaxDecodedHeaderBytes, l.MaxDecodedPayloadBytes, l.MaxTokenJSONDepth, l.MaxFacts, l.MaxFactValueBytes, l.MaxSourceSubjectBytes, l.MaxProfileIDBytes, l.MaxKidBytes, l.MaxIdentityDocumentBytes, l.MaxCatalogJSONDepth, l.MaxIssuers, l.MaxKeysPerIssuer, l.MaxTotalKeys, l.MaxProfiles, l.MaxMappings, l.MaxTotalGroupReferences, l.MaxGroupsPerMapping, l.MaxURLBytes, l.MaxSourceIDBytes, l.MaxPredicateDecimalBytes} {
		if n <= 0 || n > math.MaxInt/8 {
			return false
		}
	}
	return true
}
