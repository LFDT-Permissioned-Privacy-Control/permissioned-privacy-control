-- M5 (security audit follow-up to RD-915): codehash-pin
-- shared_infrastructure entries.
--
-- Pre-fix, an operator could tag any address as shared infrastructure.
-- Once tagged the trace validator unconditionally skipped that target
-- on every internal call. If the operator then accidentally pointed
-- a proxy (EIP-1967, beacon, transparent) at the tagged address, a
-- later proxy upgrade rotated the bytecode at that stable address and
-- the trace validator kept trusting it — a silent bypass.
--
-- Adding codehash lets the validator fetch eth_getCode at trace time,
-- hash it, and compare to the operator-attested value. Mismatch is
-- treated as untagged and the call falls through to the normal
-- ownership rules (which will deny the cross-org access the
-- attacker was trying to reach through the tag).
--
-- Existing rows have NULL codehash and continue to skip as before
-- (back-compat); operators are encouraged to populate the column on
-- every new tag and to rotate the entry on bytecode change. The admin
-- API will accept codehash on create / update.

ALTER TABLE shared_infrastructure
ADD COLUMN codehash TEXT NULL;

-- Lowercase 0x-prefixed 32-byte hex string, e.g.
-- 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470.
-- We do not enforce a CHECK constraint on the shape — application code
-- normalises to lowercase before INSERT and the validator does
-- case-insensitive comparison on read.
