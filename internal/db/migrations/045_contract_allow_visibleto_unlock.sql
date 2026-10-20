-- RD-874: per-contract opt-in to `visibleTo as event-visibility unlock`.
--
-- When this flag is true on a contract, a viewer who is (a) a member of
-- a non-anonymous group whose org_id matches the contract's owning org
-- AND (b) listed in the per-tx visibleTo for some transaction T sees
-- ALL event logs of T from this contract — bypassing the contract
-- grant's event_rules allowlist and any param_rules for that one tx.
--
-- Off (default) preserves the pre-RD-874 additive behaviour exactly:
-- visibleTo widens the response filter for already-permitted users but
-- never grants new event-level access. Admins must explicitly opt a
-- contract in via the admin API.
--
-- See decisions.md §12 and REDACTION_SPEC.md "Per-contract visibleTo
-- unlock" for the full matrix.

ALTER TABLE contracts
    ADD COLUMN allow_visibleto_unlock BOOLEAN NOT NULL DEFAULT false;

---- create above / drop below ----

ALTER TABLE contracts DROP COLUMN IF EXISTS allow_visibleto_unlock;
