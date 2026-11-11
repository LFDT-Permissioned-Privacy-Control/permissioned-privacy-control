package policyprofiles

import (
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/policybundle"
)

// DeliveryOptions selects concrete history/disclosure consumers together on
// one Core authority snapshot. BrokerMulti remains a separate bound perimeter.
func DeliveryOptions(id string) (policybundle.Options, Description, error) {
	o, d, err := HistoryOptions(id)
	if err != nil {
		return o, d, err
	}
	o.Profile = policybundle.RuntimeCreationObservedDeliveryProfile(o.Methods.Version)
	o.DisclosureLimits = disclosurepolicy.DefaultLimits()
	d.IntegrationScope = "history and retained disclosure consumer registration; actual owned services required"
	return o, d, nil
}
