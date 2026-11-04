-- WHAT: the effects marker of a finalized deployment (node_tx_effects_applied)
-- also records how many of its created addresses were refused because another
-- organization already owns them.
-- WHY (RD-1410, independent review finding 4): the refusal is decided once, in
-- the effects transaction that sets the ownership bit. Without the count, a
-- retry after that transaction committed (a crash or a failed tracking
-- finalize) found the bit set, saw no conflict and finalized the transaction
-- as fully applied.
-- AFFECTED ROWS: none rewritten. Existing markers get 0 (V2 is not deployed;
-- a marker written before this column existed reports no refusal on retry).
-- Detection: SELECT count(*) FROM node_tx_effects_applied WHERE ownership;
-- AUTHORITATIVE RECORD: the marker is bookkeeping; the refusal itself is the
-- ops.system.effects_refused event in the access-log chain, appended before
-- the effects commit. This migration file and tern schema_version. No audit-
-- table writes here.
-- EXPAND-ONLY / ROLE SEPARATION: additive column with a default; the existing
-- table grants of 078 apply (the runtime role updates markers).

ALTER TABLE node_tx_effects_applied ADD COLUMN ownership_conflicts INTEGER NOT NULL DEFAULT 0
    CHECK (ownership_conflicts >= 0);

---- create above / drop below ----

-- Forward-only: the count is part of the effects record.
