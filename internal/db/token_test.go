package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveRefreshToken(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	subject := "did:privado:test123"
	tokenHash := "test-token-hash-123"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	err := database.SaveRefreshToken(context.Background(), tokenHash, subject, expiresAt)
	require.NoError(t, err)

	// Retrieve the token
	token, err := database.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, subject, token.Subject)
	assert.Equal(t, tokenHash, token.TokenHash)
	assert.False(t, token.Revoked)
}

func TestGetRefreshToken_NotFound(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	token, err := database.GetRefreshToken(context.Background(), "non-existent-hash")
	require.NoError(t, err)
	assert.Nil(t, token)
}

func TestRevokeRefreshToken(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	subject := "did:privado:test123"
	tokenHash := "test-token-hash-456"
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Save token
	err := database.SaveRefreshToken(context.Background(), tokenHash, subject, expiresAt)
	require.NoError(t, err)

	// Revoke token
	err = database.RevokeRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)

	// Verify token is revoked
	token, err := database.GetRefreshToken(context.Background(), tokenHash)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.True(t, token.Revoked)
	assert.NotNil(t, token.RevokedAt)
}

func TestRevokeAccessToken(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	tokenID := "test-access-token-id"
	subject := "did:privado:test123"
	expiresAt := time.Now().Add(30 * time.Minute)

	err := database.RevokeAccessToken(context.Background(), tokenID, subject, expiresAt)
	require.NoError(t, err)

	// Check if token is revoked
	revoked, err := database.IsAccessTokenRevoked(context.Background(), tokenID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestIsAccessTokenRevoked_NotRevoked(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	revoked, err := database.IsAccessTokenRevoked(context.Background(), "non-existent-token-id")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestCleanupExpiredTokens(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	// Create expired refresh token
	expiredHash := "expired-token-hash"
	expiredAt := time.Now().Add(-1 * time.Hour) // 1 hour ago
	err := database.SaveRefreshToken(context.Background(), expiredHash, "did:privado:test123", expiredAt)
	require.NoError(t, err)

	// Create expired revoked token
	expiredTokenID := "expired-revoked-token"
	expiredRevokedAt := time.Now().Add(-1 * time.Hour)
	err = database.RevokeAccessToken(context.Background(), expiredTokenID, "did:privado:test123", expiredRevokedAt)
	require.NoError(t, err)

	// Cleanup
	err = database.CleanupExpiredTokens(context.Background())
	require.NoError(t, err)

	// Verify expired tokens are removed
	token, err := database.GetRefreshToken(context.Background(), expiredHash)
	require.NoError(t, err)
	assert.Nil(t, token) // Should be deleted

	revoked, err := database.IsAccessTokenRevoked(context.Background(), expiredTokenID)
	require.NoError(t, err)
	assert.False(t, revoked) // Should be deleted
}
