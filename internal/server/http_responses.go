package server

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// HTTP Response Helpers
//
// These helpers provide consistent JSON error and success responses.
// Use these instead of inline c.JSON() calls for consistent formatting.
//
// ## Error Message Conventions
//
// 1. Start with lowercase (e.g., "invalid request" not "Invalid request")
// 2. Use consistent prefixes:
//   - "invalid X" for validation errors
//   - "X not found" for missing resources
//   - "failed to X" for operation failures
//   - "missing X" for required fields/context
//
// 3. Don't expose internal error details to clients (log them instead).
//
// 4. **err.Error() must NEVER appear in a client-facing response body**
//    (RD-934). Wrapped Go error chains, pq driver errors, internal
//    identifiers, file paths, validator field names — anything that
//    can hide in `err.Error()` becomes a free side-channel an attacker
//    chains with other gadgets. Past leaks of this class: RD-916 (org
//    enumeration), RD-942 (user enumeration via FK fail), RD-944
//    (system-default fallback).
//
//    Use a generic opaque message and emit the structured details via
//    `slog.Error` / `slog.Info` with the relevant identifiers — or, for
//    the common "DB op failed → 500" pattern, use
//    `respondInternalErrorAndLog` below which does both in one call.
//
//    A CI lint (`tools/check-err-leak.sh`) blocks any new
//    `c.JSON(...err.Error())` or `respond*(c, err.Error())` from
//    landing.
//
// 5. Keep messages concise and actionable.
//
// ## Examples
//
//	respondBadRequest(c, "invalid email format")
//	respondNotFound(c, "user not found")
//	respondInternalError(c, "failed to process request")
//	respondUnauthorized(c, "missing or invalid token")
//
//	// DB op failed — wrong pattern (leaks err.Error to client):
//	if err := s.db.CreateContract(ctx, c); err != nil {
//	    c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
//	    return
//	}
//
//	// DB op failed — right pattern (generic client response + slog for operators):
//	if err := s.db.CreateContract(ctx, c); err != nil {
//	    respondInternalErrorAndLog(c, "failed to create contract",
//	        "create contract: db insert failed",
//	        "org_id", c.OrgID, "address", c.Address, "err", err)
//	    return
//	}

func respondBadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": message})
}

func respondUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": message})
}

func respondForbidden(c *gin.Context, message string) {
	c.JSON(http.StatusForbidden, gin.H{"error": message})
}

func respondNotFound(c *gin.Context, message string) {
	c.JSON(http.StatusNotFound, gin.H{"error": message})
}

func respondConflict(c *gin.Context, message string) {
	c.JSON(http.StatusConflict, gin.H{"error": message})
}

func respondTooManyRequests(c *gin.Context, message string) {
	c.JSON(http.StatusTooManyRequests, gin.H{"error": message})
}

func respondInternalError(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, gin.H{"error": message})
}

func respondBadGateway(c *gin.Context, message string) {
	c.JSON(http.StatusBadGateway, gin.H{"error": message})
}

func respondServiceUnavailable(c *gin.Context, message string) {
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": message})
}

// AndLog variants — emit a structured slog entry before responding so
// the operator gets the diagnostic details that must never reach the
// client. logMsg is the slog message; logKVs are passed verbatim to
// slog (use the standard "key", value, ... convention). clientMsg is
// the opaque message that goes on the wire.
//
// Designed for the common "operation failed → opaque response + log
// the underlying err" pattern. RD-934.

func respondBadRequestAndLog(c *gin.Context, clientMsg, logMsg string, logKVs ...any) {
	slog.Warn(logMsg, logKVs...)
	respondBadRequest(c, clientMsg)
}

func respondNotFoundAndLog(c *gin.Context, clientMsg, logMsg string, logKVs ...any) {
	slog.Info(logMsg, logKVs...)
	respondNotFound(c, clientMsg)
}

func respondConflictAndLog(c *gin.Context, clientMsg, logMsg string, logKVs ...any) {
	slog.Info(logMsg, logKVs...)
	respondConflict(c, clientMsg)
}

func respondInternalErrorAndLog(c *gin.Context, clientMsg, logMsg string, logKVs ...any) {
	slog.Error(logMsg, logKVs...)
	respondInternalError(c, clientMsg)
}

func respondBadGatewayAndLog(c *gin.Context, clientMsg, logMsg string, logKVs ...any) {
	slog.Error(logMsg, logKVs...)
	respondBadGateway(c, clientMsg)
}

func respondServiceUnavailableAndLog(c *gin.Context, clientMsg, logMsg string, logKVs ...any) {
	slog.Error(logMsg, logKVs...)
	respondServiceUnavailable(c, clientMsg)
}

// Success response helpers

func respondOK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

func respondCreated(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, data)
}

func respondMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"message": message})
}

func respondDeleted(c *gin.Context, resourceType string) {
	c.JSON(http.StatusOK, gin.H{"message": resourceType + " deleted"})
}
