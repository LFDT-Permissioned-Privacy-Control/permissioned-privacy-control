package policyprofiles

import (
	"fmt"
	"privacy-proxy/internal/policybundle"
)

// HistoryOptions is explicit trusted registration, not source-capability
// discovery. Existing Options preserves its default behavior and old digests.
func HistoryOptions(id string) (policybundle.Options, Description, error) {
	if id != policybundle.RuntimeCreationObservedProfileID {
		return policybundle.Options{}, Description{}, fmt.Errorf("history consumer requires creation-observed profile")
	}
	o, d, err := Options(id)
	if err != nil {
		return o, d, err
	}
	o.Profile = policybundle.RuntimeCreationObservedHistoryProfile(o.Methods.Version)
	d.IntegrationScope = "current ordinary history consumer registration; actual owned service required"
	return o, d, nil
}
