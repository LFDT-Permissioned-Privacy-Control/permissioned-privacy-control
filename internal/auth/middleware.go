package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// AccessCookieName is the cookie that carries the PP access JWT for browser
// navigations (RD-1008). The Authorization: Bearer header still takes
// precedence at the middleware so existing API clients keep working — the
// cookie only fills the gap when the browser navigates to a server-side
// endpoint (e.g. /oauth/authorize) that has no JS to attach the header.
const AccessCookieName = "pp_access"

// SetAccessCookie writes the access JWT as an HttpOnly cookie scoped to the
// current host. SameSite=Lax lets the cookie travel on top-level cross-
// subdomain navigation under the same registrable domain (proxy and
// block-explorer on the same eTLD+1 — e.g. *.gateway.fm), which is what
// silent SSO depends on. Secure is enabled whenever the request is HTTPS
// (or behind an HTTPS-terminating proxy advertising X-Forwarded-Proto), so
// the cookie stays usable on local dev (http://localhost) while staying
// Secure in production.
func SetAccessCookie(c *gin.Context, accessToken string, ttl time.Duration) {
	secure := c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     AccessCookieName,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearAccessCookie expires the access-token cookie. Idempotent: a no-op
// for clients that never had the cookie set.
func ClearAccessCookie(c *gin.Context) {
	secure := c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     AccessCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// extractAccessToken reads the access JWT from either the Authorization
// header (preferred — API clients) or the access cookie (browser
// navigations). Returns the empty string when neither carries a token.
// The boolean indicates whether the Authorization header was present but
// malformed; callers should treat that as a hard 401 (the user-supplied
// something but it wasn't a Bearer token) rather than falling back to
// anonymous behaviour.
func extractAccessToken(c *gin.Context) (token string, malformedHeader bool) {
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		parts := strings.Split(authHeader, " ")
		// The auth-scheme token is case-insensitive (RFC 7235 §2.1; RFC 6750
		// inherits it) — accept "Bearer" / "bearer" / "BEARER" alike. The
		// credential in parts[1] is still validated by the caller regardless.
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return "", true
		}
		return parts[1], false
	}
	if cookie, err := c.Request.Cookie(AccessCookieName); err == nil {
		return cookie.Value, false
	}
	return "", false
}

// JWTAuthMiddleware validates JWT access tokens
func JWTAuthMiddleware(jwtService *JWTService, db RevocationChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, malformed := extractAccessToken(c)
		if malformed {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			c.Abort()
			return
		}
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			c.Abort()
			return
		}

		// Validate token
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			if err == ErrExpiredToken {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			}
			c.Abort()
			return
		}

		// Check if token is revoked (if revocation checker is available)
		if db != nil {
			// Use hash of token as ID for revocation tracking
			tokenID := getTokenID(tokenString)
			revoked, err := db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check token revocation"})
				c.Abort()
				return
			}
			if revoked {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
				c.Abort()
				return
			}
		}

		// Store claims in context for use in handlers
		c.Set("subject", claims.Subject)
		c.Set("kyc", claims.KYC)
		c.Set("claims", claims)

		c.Next()
	}
}

// OptionalJWTAuthMiddleware validates JWT if present, but allows anonymous requests.
//
// L5 (security audit): the middleware previously trusted CheckAccess
// downstream to enforce the banned-user check. That made the property
// "no banned user can act through this proxy" depend on every JSON-RPC
// consumer piping through CheckAccess — easy to silently regress when
// a future feature reuses OptionalJWT for a new endpoint. Now Banned
// is enforced here when the RevocationChecker also implements the
// BannedChecker extension; the regular *db.DB satisfies both so the
// production path is upgraded automatically. Implementations that
// only satisfy RevocationChecker (test fixtures) keep the previous
// behaviour. The production store's conformance to BannedChecker is
// pinned at compile time (see the `var _ auth.BannedChecker` assertion
// in internal/server, RD-1164 #14), so the ban check can never be
// silently skipped in production by a dropped/renamed method.
func OptionalJWTAuthMiddleware(jwtService *JWTService, db RevocationChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, malformed := extractAccessToken(c)
		if malformed {
			// Header present but not a Bearer token — fail rather than
			// silently treating as anonymous (security measure).
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			c.Abort()
			return
		}
		if tokenString == "" {
			// Truly anonymous — neither header nor cookie. Allowed for
			// /oauth/authorize so the OAuth flow can fall through to
			// interactive Privado for unauthenticated users.
			c.Next()
			return
		}
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			// If token is invalid/expired, we fail (security measure)
			if err == ErrExpiredToken {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			}
			c.Abort()
			return
		}

		if db != nil {
			tokenID := getTokenID(tokenString)
			revoked, err := db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check token revocation"})
				c.Abort()
				return
			}
			if revoked {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
				c.Abort()
				return
			}
			if banChk, ok := db.(BannedChecker); ok {
				banned, err := banChk.IsUserBannedBySubject(c.Request.Context(), claims.Subject)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check user ban status"})
					c.Abort()
					return
				}
				if banned {
					// L5: deny with the same opaque JSON-RPC error shape
					// the downstream processor emits for RBAC denials —
					// pre-fix the JSON-RPC processor's CheckAccess
					// translated "user is banned" into the canonical
					// 404 / "method not found" response. Mirroring that
					// shape here keeps the ban status from leaking to
					// the caller (per CLAUDE.md security review:
					// "error message exposure" — never echo the
					// denial reason). The middleware sits on JSON-RPC
					// roots and the explorer route group; both treat
					// 404 + method-not-found as an acceptable opaque
					// deny.
					c.JSON(http.StatusNotFound, gin.H{"error": "method not found"})
					c.Abort()
					return
				}
			}
		}

		c.Set("subject", claims.Subject)
		c.Set("kyc", claims.KYC)
		c.Set("claims", claims)

		c.Next()
	}
}

// RevocationChecker interface for checking token revocation
type RevocationChecker interface {
	IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error)
}

// BannedChecker is an optional extension to RevocationChecker that
// lets OptionalJWTAuthMiddleware enforce user bans at the auth
// boundary. The production *db.DB type implements it; test fixtures
// that don't are not affected.
type BannedChecker interface {
	IsUserBannedBySubject(ctx context.Context, subject string) (bool, error)
}

// getTokenID generates a hash ID from token string for revocation tracking
func getTokenID(tokenString string) string {
	hash := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(hash[:])
}
