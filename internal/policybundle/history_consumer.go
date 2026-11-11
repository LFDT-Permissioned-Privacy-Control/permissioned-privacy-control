package policybundle

import "slices"

const (
	CapabilityRuntimeHistory   = "runtime.history-read/v1"
	CapabilityVisibleToHistory = "privacy.visible-to-history"
)

// RuntimeCreationObservedHistoryProfile selects one compiled consumer, never a
// feature requested by an untrusted source document. The profile/evaluator IDs
// stay fixed; its explicit inferred capability changes the approved manifest.
func RuntimeCreationObservedHistoryProfile(methodVersion string) ValidationProfile {
	p := RuntimeCreationObservedProfile(methodVersion)
	p.historyConsumer = true
	return p
}

// HistoryConsumerEnabled reports trusted selection AND an explicit approved
// requirement. It proves neither permission nor an installed runtime handler.
func (s *CatalogSnapshot) HistoryConsumerEnabled() bool {
	return s != nil && s.historyConsumer && s.metadata.Profile == RuntimeCreationObservedProfileID && slices.Contains(s.requirements.Capabilities, CapabilityRuntimeHistory)
}
