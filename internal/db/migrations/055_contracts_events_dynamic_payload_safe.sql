-- M15 (security audit follow-up): per-contract opt-out for dynamic-payload
-- event redaction.
--
-- Pre-M15, RedactLogs scanned only AddressTy + bytes32-typed static
-- slots of an event's non-indexed params for embedded private
-- addresses. Dynamic types — `bytes`, `string`, dynamic arrays,
-- dynamic structs — were passed through verbatim. Contracts that
-- embed addresses inside a `bytes` payload (bridge contracts,
-- forwarder/relayer patterns, smart-wallet flows, etc.) leaked
-- foreign-org addresses to any viewer who could read the event log.
--
-- Default-fix (close-by-default): RedactLogs and the RPC-layer
-- FilterEventLogs now DROP the entire log for non-Full viewers
-- (anything except admins, participants, or visibleTo-listed DIDs)
-- when the matching event's ABI declares any dynamic non-indexed
-- parameter. Conservative; biased toward over-redaction.
--
-- Per-contract opt-out (this migration): operators can mark a
-- contract as "events_allow_dynamic_payload = true" to disable the
-- new drop logic for THAT contract specifically. Use cases:
--   - Standard ERC-20 / ERC-721 contracts with no addresses in
--     `string` symbol / `string` name / `bytes` metadata.
--   - Contracts whose dynamic payloads are known to be free of
--     foreign-org address material (e.g., gas-only fee receipts,
--     timestamp ledgers).
--
-- Defaults to FALSE — admins must explicitly opt out per contract.
-- The flag is admin-only via the PUT endpoint.

ALTER TABLE contracts
ADD COLUMN events_allow_dynamic_payload BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN contracts.events_allow_dynamic_payload IS
'M15 opt-out: when TRUE, RedactLogs / FilterEventLogs pass through events with dynamic non-indexed params without dropping for non-Full viewers. Admin-set, default FALSE (close-by-default).';
