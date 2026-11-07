# Current wallet association source

`disclosurewallet.Reader` supplies a bounded current association snapshot for
protected-data adapters. It borrows the existing `walletsql.OpenReader` store
and adds no tables, grants, writes, persistent cache or HTTP endpoints.

The reader derives one union of the case's target actors and recipient, up to
257 actors. One SQL statement reads the selected ready wallet namespace and
its current, nonrevoked `eip191_v2` associations. The global 4,097th tuple is an
overflow sentinel: a snapshot contains at most 4,096 complete actor/address
tuples, or fails with `ErrTooBroad`. The same wallet linked to two actors counts
as two tuples. A ready store with no selected links is a valid empty result;
an absent, unready or mismatched recovery state fails. Unsupported relation
shapes and row-level security also fail, so hidden links cannot appear empty.

Canonical ordering follows actor bytes then address bytes after establishing
that the complete set fits the limit. The snapshot reference binds the network,
wallet namespace, recovery generation and coverage, source plan, exact selected
actor set including actors with no links, and each tuple's stored acceptance
time. An observation timestamp is separate and does not change the reference.
Cursor resumption reads the current set again and rejects a changed reference.

`CheckCurrent` performs another bounded sampled read before exposure. It detects
committed selected-link changes and recovery changes visible to that read. It
holds no connection or transaction between calls. An unlink committed after
this final sample may race with later exposure audit and HTTP output; this
component provides no cross-store revocation fence. Each SQL read has a two
second deadline within its caller's deadline.

These are link-time operational associations, not evidence of historical
ownership, transaction authorship, historical data organization, membership or
permission. Recipient links can supply `Mine` metadata without enlarging the
case's target scope. An empty wallet set does not establish historical coverage
or make an unknown report complete or not applicable: the protected-read
composition must still qualify every required source, including history.
Activity-only resources do not use this component.

Recovery uses the existing offline protocol: drain every replica, select a new
generation, import permanent revocations, validate the stored links and publish
an explicit completeness attestation. Old state and snapshot references cannot
rebind to the new generation. The database operator and existing wallet writer
remain trusted; the reader has no access to proof messages or signatures and
does not authenticate arbitrary operator edits cryptographically.
