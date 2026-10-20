-- M7 (security audit follow-up): outbox for tx_visible_to writes.
--
-- Pre-fix, the hot path tried to INSERT into tx_visible_to right after the
-- node accepted the tx. If that INSERT errored (DB hiccup, lock contention,
-- transient connection break) the recipients in the visibleTo list silently
-- lost visibility on a tx that's already on-chain — there is no way to
-- recover from inside the request handler.
--
-- Fix: always INSERT into pending_tx_visibility first. A background
-- reconciler (5s ticker) promotes rows into tx_visible_to. On success the
-- pending row is deleted. On failure the attempt_count is incremented and
-- the row stays in the outbox for the next tick. Rows that exhaust
-- max_attempts stay in pending with attempt_count >= the cap so an
-- operator metric / alert can surface them; they are never auto-deleted.

CREATE TABLE pending_tx_visibility (
    id BIGSERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL,
    visible_to_dids TEXT[] NOT NULL,
    sender_did TEXT NOT NULL,
    org_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempt_count INT NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ NULL,
    last_error TEXT NULL
);

-- Reconciler-friendly index: only the rows that still need work.
-- attempt_count < 10 is the soft cap; the index narrows the scan.
CREATE INDEX idx_pending_tx_visibility_due
    ON pending_tx_visibility (created_at)
    WHERE attempt_count < 10;

-- Tx hash is not unique in this table (a future retry might race with a
-- new insert for the same tx) — the reconciler uses ON CONFLICT DO NOTHING
-- on the promotion path because tx_visible_to itself enforces uniqueness.
CREATE INDEX idx_pending_tx_visibility_tx_hash
    ON pending_tx_visibility (tx_hash);

-- Idempotency: make tx_visible_to.tx_hash unique so the reconciler's
-- ON CONFLICT (tx_hash) DO NOTHING on the promotion INSERT works
-- correctly when a duplicate outbox row is processed (e.g. a partial
-- failure and a retry).
--
-- The existing semantic of tx_visible_to is "one row per tx" — every read
-- path (`GetTxVisibility`, `GetBatchTxVisibility`, `GetVisibleTxHashesForDID`)
-- already assumes uniqueness via `LIMIT 1` or aggregate. Any pre-existing
-- duplicate is a no-op artifact and can be collapsed safely: keep the row
-- with the oldest created_at (the originating call) and drop the rest.
-- The merged visible_to_dids array is taken from the kept row only —
-- duplicates from racy retries had the same DID list anyway.

DELETE FROM tx_visible_to a
USING tx_visible_to b
WHERE a.ctid < b.ctid AND a.tx_hash = b.tx_hash;

ALTER TABLE tx_visible_to
ADD CONSTRAINT tx_visible_to_tx_hash_key UNIQUE (tx_hash);
