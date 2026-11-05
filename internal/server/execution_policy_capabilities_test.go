package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/config"
)

func releaseCutConsumerConfig(t *testing.T) config.NodePolicyConfig {
	t.Helper()
	c := config.NodePolicyConfig{
		Mode: "reth", URL: "http://127.0.0.1:1", Token: "release-cut-test-private-token",
		PrivateKeyFile: "/not-read-by-capability", KeyID: "release-cut", ChainID: 31337,
		DeploymentID: "release-cut", ConsumerID: "producer", FactTTL: 30 * time.Second,
		PublishInterval: time.Second, IdentityTTL: time.Minute,
	}
	require.NoError(t, c.Validate())
	return c
}

func TestExecutionPolicyCapabilitiesDistinguishConfiguredSupportFromReadiness(t *testing.T) {
	t.Setenv("OPS_APPROVAL_TARGETS", "guard-v1.example:50051")
	legacy := &Server{config: &config.Config{NodePolicy: config.NodePolicyConfig{Mode: "legacy"}}}
	status := legacy.executionStatus(context.Background())
	require.True(t, status.Ready, "ordinary legacy readiness remains unchanged")
	require.Equal(t, "none", status.PolicyCapabilities.ConfiguredConsumer)
	require.False(t, status.PolicyCapabilities.ActivationSupported)
	require.True(t, status.PolicyCapabilities.CandidateReviewSupported)
	require.True(t, status.PolicyCapabilities.ReferenceSimulationSupported)
	require.False(t, status.PolicyCapabilities.NodePreviewSupported)
	require.False(t, status.PolicyCapabilities.NodeTransactionStatusSupported)
	require.False(t, status.PolicyCapabilities.NodeOwnershipRecoverySupported)
	require.Equal(t, executionConsumerUnavailable, status.PolicyCapabilities.UnavailableReason)

	// No bridge, network request, current facts or compiler process is needed to
	// describe the implementation selected by a valid server configuration.
	guarded := &Server{config: &config.Config{NodePolicy: releaseCutConsumerConfig(t)}}
	status = guarded.executionStatus(context.Background())
	require.False(t, status.Ready)
	require.Equal(t, "guarded-reth", status.PolicyCapabilities.ConfiguredConsumer)
	require.True(t, status.PolicyCapabilities.ActivationSupported)
	require.False(t, status.PolicyCapabilities.ReferenceSimulationSupported)
	require.True(t, status.PolicyCapabilities.NodePreviewSupported)
	require.True(t, status.PolicyCapabilities.NodeTransactionStatusSupported)
	require.True(t, status.PolicyCapabilities.NodeOwnershipRecoverySupported)
	require.Empty(t, status.PolicyCapabilities.UnavailableReason)
}

func TestExecutionPolicyCapabilitiesDoNotInferUnknownConsumerSupport(t *testing.T) {
	for _, c := range []config.NodePolicyConfig{{}, {Mode: "future"}, {Mode: "reth"}} {
		capability := executionPolicyCapabilitiesForConfig(c)
		require.Equal(t, "none", capability.ConfiguredConsumer)
		require.False(t, capability.ActivationSupported)
		require.True(t, capability.CandidateReviewSupported)
		require.True(t, capability.ReferenceSimulationSupported)
	}
}
