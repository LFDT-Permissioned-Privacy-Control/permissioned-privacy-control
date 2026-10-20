-- RD-993: audit log for first-party silent SSO grants.
--
-- Each row records one /oauth/session/:id/silent-complete success: a
-- tier-1 user authenticated to PP bounced through OAuth back to a
-- first-party client (e.g. block-explorer) and we issued an auth code
-- without re-prompting them. SIEM forwarding (internal/audit/siem.go)
-- is layered on top.
--
-- Schema choices:
--   * actor_did: the DID of the user who silently completed the flow.
--     Captured from the caller's JWT at the time of /silent-complete.
--   * client_id: which first-party RP got the grant (must be on the
--     OAUTH_FIRST_PARTY_CLIENTS allowlist; recorded so a misconfigured
--     allowlist is visible in audit even if it's later corrected).
--   * redirect_uri_hash: sha256 of the redirect URI the session was
--     bound to. We don't store the raw URI to keep the table small and
--     keep operator-controlled paths out of audit retention; a hash is
--     enough to correlate against the OAUTH_FIRST_PARTY_CLIENTS +
--     allowed-redirect-URI deploy config.
--   * correlation_id: lines up with the access_logs row for the same
--     request, so a reviewer can pivot to the upstream context.

CREATE TABLE oauth_silent_sso_log (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_did         TEXT        NOT NULL,
    client_id         TEXT        NOT NULL,
    redirect_uri_hash CHAR(64)    NOT NULL,        -- sha256 of the redirect_uri, hex
    correlation_id    UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Browse by actor (which silent grants did this user accumulate?)
CREATE INDEX idx_oauth_silent_sso_log_actor ON oauth_silent_sso_log (actor_did, created_at DESC);
-- Browse by client (which RP got how many silent grants?)
CREATE INDEX idx_oauth_silent_sso_log_client ON oauth_silent_sso_log (client_id, created_at DESC);

---- create above / drop below ----

DROP INDEX IF EXISTS idx_oauth_silent_sso_log_client;
DROP INDEX IF EXISTS idx_oauth_silent_sso_log_actor;
DROP TABLE IF EXISTS oauth_silent_sso_log;
