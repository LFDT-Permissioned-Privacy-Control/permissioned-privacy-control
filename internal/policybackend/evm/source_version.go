package evm

import (
	"fmt"

	"privacy-proxy/internal/policycore"
)

// UnsupportedPolicyError prevents a native-only source from being compiled to
// an artifact that would omit one of its constraints.
type UnsupportedPolicyError struct {
	Version string
	Feature string
}

func (e *UnsupportedPolicyError) Error() string {
	return fmt.Sprintf("policydsl: EVM backend does not support source %q or feature %q", e.Version, e.Feature)
}

func checkSupportedPolicy(v *policycore.Validated) error {
	if v == nil || v.Policy() == nil {
		return fmt.Errorf("policydsl: no validated policy to compile")
	}
	p := v.Policy()
	if p.APIVersion != policycore.APIVersion {
		return &UnsupportedPolicyError{Version: p.APIVersion}
	}
	for _, binding := range p.Bindings {
		for _, rule := range binding.Allow {
			if rule.MinDepth != nil {
				return &UnsupportedPolicyError{Version: p.APIVersion, Feature: "minDepth"}
			}
		}
	}
	return nil
}
