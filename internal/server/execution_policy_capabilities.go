package server

import (
	"context"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/db"
)

const executionConsumerUnavailable = "execution_consumer_unavailable"

// executionPolicyCapabilitiesForConfig describes configured support. Server
// construction validates this configuration before opening services and aborts
// if the selected implementation cannot be initialized. Do not depend on a
// live node or an initialized bridge here: doing so would block bootstrap and
// confuse an approved desired revision with its eventual application.
func executionPolicyCapabilitiesForConfig(c config.NodePolicyConfig) apimodels.ExecutionPolicyCapabilities {
	result := apimodels.ExecutionPolicyCapabilities{
		ConfiguredConsumer:           "none",
		CandidateReviewSupported:     true,
		ReferenceSimulationSupported: true,
		UnavailableReason:            executionConsumerUnavailable,
	}
	if c.Validate() != nil || !c.Enabled() {
		return result
	}
	result.ConfiguredConsumer = "guarded-reth"
	result.ActivationSupported = true
	// Reth mode directs execution previews to the node and closes the old
	// described-frame reference-simulation route with its existing 409.
	result.ReferenceSimulationSupported = false
	result.NodePreviewSupported = true
	result.NodeTransactionStatusSupported = true
	result.NodeOwnershipRecoverySupported = true
	result.UnavailableReason = ""
	return result
}

func (s *Server) executionPolicyCapabilities() apimodels.ExecutionPolicyCapabilities {
	var c config.NodePolicyConfig
	if s != nil && s.config != nil {
		c = s.config.NodePolicy
	}
	return executionPolicyCapabilitiesForConfig(c)
}

func executionPolicyConsumerError() error {
	return db.ConfigurationUnavailable("%s: this deployment can prepare and review execution policies, but has no configured runtime to enforce them", executionConsumerUnavailable)
}

// authorizeConfigurationPolicyActivation is deliberately separate from the
// authority callback also used by withdrawal. Only activation requires a live
// policy consumer, and an execution sibling must not bypass this check through
// a URL for another stream. The DB invokes this over the complete locked set.
func (s *Server) authorizeConfigurationPolicyActivation(ctx context.Context, tx *db.Tx, view db.ConfigurationActivation) error {
	if err := s.authorizeConfigurationActivation(ctx, tx, view); err != nil {
		return err
	}
	if s.executionPolicyCapabilities().ActivationSupported {
		return nil
	}
	for _, candidate := range view.Candidates {
		if candidate.Kind == configuration.ExecutionRules {
			return executionPolicyConsumerError()
		}
	}
	return nil
}
