package policybundle

import "slices"

const CapabilityRuntimeDisclosure = "runtime.disclosure-read/v1"

// RuntimeCreationObservedDeliveryProfile is trusted consumer registration.
// Existing plain/history selections stay closed. The inferred capability and
// exact disclosure document change the approved manifest, not its authority.
func RuntimeCreationObservedDeliveryProfile(methodVersion string) ValidationProfile {
	p := RuntimeCreationObservedHistoryProfile(methodVersion)
	p.disclosureConsumer = true
	return p
}
func (s *CatalogSnapshot) DisclosureConsumerEnabled() bool {
	return s != nil && s.disclosureConsumer && s.historyConsumer && s.metadata.Profile == RuntimeCreationObservedProfileID && s.disclosure != nil && s.compliance != nil && slices.Contains(s.requirements.Capabilities, CapabilityRuntimeDisclosure)
}
