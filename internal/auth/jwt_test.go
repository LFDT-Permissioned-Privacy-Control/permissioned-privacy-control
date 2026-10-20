package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTService_IssueAccessToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTService_ValidateAccessToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a token
	subject := "did:privado:test123"
	kyc := true
	token, err := service.IssueAccessToken(subject, kyc)
	require.NoError(t, err)

	// Validate the token
	claims, err := service.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.Equal(t, subject, claims.Subject)
	assert.Equal(t, kyc, claims.KYC)
	assert.True(t, claims.ExpiresAt.Time.After(time.Now()))
}

func TestJWTService_ValidateAccessToken_Expired(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", -1*time.Hour, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue an expired token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	// Validation should fail
	_, err = service.ValidateAccessToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestJWTService_ValidateAccessToken_Invalid(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Try to validate an invalid token
	_, err = service.ValidateAccessToken("invalid.token.here")
	assert.Error(t, err)
	// Check if error is ErrInvalidToken (using errors.Is for wrapped errors)
	assert.ErrorIs(t, err, ErrInvalidToken, "error should be or wrap ErrInvalidToken")
}

func TestJWTService_IssueRefreshToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	token, err := service.IssueRefreshToken("did:privado:test123")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTService_ValidateRefreshToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a refresh token
	subject := "did:privado:test123"
	token, err := service.IssueRefreshToken(subject)
	require.NoError(t, err)

	// Validate the token
	claims, err := service.ValidateRefreshToken(token)
	require.NoError(t, err)
	assert.Equal(t, subject, claims.Subject)
	assert.True(t, claims.ExpiresAt.Time.After(time.Now()))
}

func TestJWTService_ValidateRefreshToken_WrongSecret(t *testing.T) {
	service1, err := NewJWTService("secret1", "refresh-secret1", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	service2, err := NewJWTService("secret2", "refresh-secret2", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue token with service1
	token, err := service1.IssueRefreshToken("did:privado:test123")
	require.NoError(t, err)

	// Try to validate with service2 (different secret)
	_, err = service2.ValidateRefreshToken(token)
	assert.Error(t, err)
}

// TestJWTService_RotationWindow exercises RD-1164 #15: after a secret rotation,
// the new secret signs while a token issued under the previous secret keeps
// validating (until it expires), so rotation does not force a mass logout.
func TestJWTService_RotationWindow(t *testing.T) {
	// "Old" service issued tokens under the outgoing secrets.
	old, err := NewJWTService("old-access", "old-refresh", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	accessOld, err := old.IssueAccessToken("did:privado:rotate", true)
	require.NoError(t, err)
	refreshOld, err := old.IssueRefreshToken("did:privado:rotate")
	require.NoError(t, err)

	// "New" service signs with the rotated-in secrets. Without a window it must
	// reject the old token...
	fresh, err := NewJWTService("new-access", "new-refresh", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	_, err = fresh.ValidateAccessToken(accessOld)
	assert.ErrorIs(t, err, ErrInvalidToken, "without a rotation window the old-secret token must be rejected")

	// ...but once the outgoing secrets are registered as validation-only, the
	// old token validates again.
	fresh.SetValidationSecrets([]string{"old-access"}, []string{"old-refresh"})

	claims, err := fresh.ValidateAccessToken(accessOld)
	require.NoError(t, err, "old-secret access token should validate within the rotation window")
	assert.Equal(t, "did:privado:rotate", claims.Subject)

	rclaims, err := fresh.ValidateRefreshToken(refreshOld)
	require.NoError(t, err, "old-secret refresh token should validate within the rotation window")
	assert.Equal(t, "did:privado:rotate", rclaims.Subject)

	// A token signed under a secret that is neither current nor previous stays rejected.
	stranger, err := NewJWTService("stranger-access", "stranger-refresh", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	strangerTok, err := stranger.IssueAccessToken("did:privado:stranger", false)
	require.NoError(t, err)
	_, err = fresh.ValidateAccessToken(strangerTok)
	assert.ErrorIs(t, err, ErrInvalidToken, "unknown-secret token must never validate")

	// New tokens are still signed with the current secret (round-trips on fresh).
	accessNew, err := fresh.IssueAccessToken("did:privado:rotate", true)
	require.NoError(t, err)
	_, err = fresh.ValidateAccessToken(accessNew)
	require.NoError(t, err)
	// ...and the old service (no window) must NOT accept the new-secret token.
	_, err = old.ValidateAccessToken(accessNew)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

// TestJWTService_RotationWindow_ExpiredNotRevived proves the window never
// extends a token's lifetime: an expired old-secret token stays denied.
func TestJWTService_RotationWindow_ExpiredNotRevived(t *testing.T) {
	old, err := NewJWTService("old-access", "old-refresh", -1*time.Hour, -1*time.Hour)
	require.NoError(t, err)
	expired, err := old.IssueAccessToken("did:privado:rotate", true)
	require.NoError(t, err)

	fresh, err := NewJWTService("new-access", "new-refresh", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	fresh.SetValidationSecrets([]string{"old-access"}, []string{"old-refresh"})

	_, err = fresh.ValidateAccessToken(expired)
	assert.ErrorIs(t, err, ErrExpiredToken, "an expired token must stay denied even within the rotation window")
}

// TestJWTService_SetValidationSecrets_IgnoresBlank ensures a trailing comma /
// unset var (empty string) never becomes an accepted all-zero-length key.
func TestJWTService_SetValidationSecrets_IgnoresBlank(t *testing.T) {
	fresh, err := NewJWTService("new-access", "new-refresh", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	fresh.SetValidationSecrets([]string{"", ""}, []string{""})

	// A token signed with an empty-string secret must not validate: blank
	// previous entries are dropped, so they never become an accepted key.
	blankSigner := &JWTService{accessSecret: []byte(""), refreshSecret: []byte(""), accessTTL: 30 * time.Minute, refreshTTL: time.Hour}
	tok, err := blankSigner.IssueAccessToken("did:privado:blank", false)
	require.NoError(t, err)
	_, err = fresh.ValidateAccessToken(tok)
	assert.ErrorIs(t, err, ErrInvalidToken, "blank previous secrets must be ignored, not accepted")
}

func TestHashToken(t *testing.T) {
	token := "test-token-123"
	hash1 := HashToken(token)
	hash2 := HashToken(token)

	// Same token should produce same hash
	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 64) // SHA256 produces 64 hex characters

	// Different token should produce different hash
	hash3 := HashToken("different-token")
	assert.NotEqual(t, hash1, hash3)
}
