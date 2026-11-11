# Current history read facts

`historyfacts.Factory` verifies one original OPS access JWT against its selected
immutable policy snapshot. It checks the exact selected organization, method,
required claims and unambiguous credential reference before reading wallets.
There is no default-bank selection or anonymous fallback. The context retains
the verified View and a SHA-256 digest of the original signed token, not the raw
token. This is an internal source helper; it installs no history or Explorer
route and does not record or release an HTTP response.

The independently configured wallet service origin, environment, chain,
genesis, deployment, generation and coverage must match the actual resolver.
The current actor's active proved addresses supply plain own-address visibility.
The final check reloads the same actor and compares the same current-set version
and source state. Removal, reassignment, unavailable storage or a changed current
set rejects delivery. This is a current-set comparison, not a durable mutation
counter or a promise to detect every intermediate change. The wallet API rejects
relinking an already revoked association; this helper adds no relinking feature.

Current registered contract grants and admin facts apply only when the
contract's owner is the selected organization. Another organization's grants in
the same token cannot be combined with the selected method or credential. A
readonly-admin bit alone supplies neither a contract association nor admin
access. Own-wallet visibility and plain state/deployer association do not create
an event grant. Event rules reuse the shared union helper in the View's stable
grant-ID order. Dataset admin access requires a positively registered owning
contract; an unknown EOA-to-EOA row has no inferred bank owner. The strict profile
does not acquire or fabricate a transaction-share pass and does not use
transaction listings or dataset admin bypasses.
Its immutable startup mode permits an absent share source. A supplied source is
still checked against independent metadata; standard mode requires it.

Ordinary address visibility starts hidden. An own active wallet or one of the
fixed ordinary V1 precompile floor at addresses 1 through 9 is Full. Later native
precompiles require fork qualification that this history context does not infer.
A selected-owner
registered contract with current association is Full; another registered
contract is Redacted. Missing code, an absent row, factory namespace, unknown
address or a failed source never makes an address public. The separate emitter
facts must be used for event decisions; a generic Full address is insufficient.

`admissionsql.ShareReader` borrows an already opened schema-v3 restricted reader
Store. It owns no pool and exposes no writer callback. Independent expected
metadata binds the whole network tuple, generation, coverage and fixed share
schema purpose. Construction checks the actual Store mode and schema; actual
network readiness and tuple equality are checked in each read transaction.
Those checks identify a trusted operational source, not cryptographic proof of
arbitrary database contents.

Each exact query contains at most 1,024 unique nonzero hashes. One read-only
REPEATABLE READ transaction checks state and reads the existing immutable
`tx_shares` rows. Present malformed data is an error. Nested SQL CASE guards bound
array dimensions, cardinality, storage size, actor lengths, fixed byte lengths,
numeric scales and finite timestamps before JSON projection or network decoding.
The transport projection is at most 8 KiB per row; decoding and the whole retained
observation are charged against a 16 MiB ceiling. Existing limits of 32 immutable
ActorID recipients per share remain unchanged. No new table, index, role or grant
is needed.

Only known successful COMMIT produces a pass. It retains the actual reader
identity, independent binding, exact query, immutable positives, explicit absence
and deterministic digest. A final read on the same reader checks state and all
original positives. Changes or disappearance reject delivery. A newly arriving
share for an originally absent hash can affect a subsequent request; it cannot
widen this context's decisions. Listing follows the ActorID, so a new wallet
owner does not inherit another actor's old recipient entry.

All stages share the earlier of the original caller deadline and a maximum
20-second operation deadline, including a caller using Background. The context
stores only that deadline and the original Done channel. Temporary acquisition
children are canceled on return and are never retained as the publication fence.
Each SQL read is additionally bounded by the existing five-second transaction,
three-second statement and one-second lock limits. There is no fresh final
operation budget, retry worker, permission cache or per-transaction capture write.

The serving owner must append its actual Recorder completion before releasing
protected bytes, call this context's final wallet/share recheck, check its actual
original node/index source observation, and check the same original View/context
after its last I/O. These are ordered samples across separate stores, not an
atomic distributed snapshot or a guarantee that revocation cannot occur after
the last sample. JWT expiry is never renewed by revalidation. A newly selected
Git revision requires the newly selected immutable snapshot; this helper is not
a hot-reload or rollout coordinator.

The approved creation-observed loader currently rejects the visibleTo-unlock
flag (`policybundle/catalog.go`, `AllowVisibleToUnlock` branch). Dynamic-event
payloads already infer the existing `privacy.dynamic-event-payload` capability;
the approved manifest must declare it, as exercised by the dynamic-payload
positive in `policybundle/semantics_test.go`. Those loader rules remain in place.
A visibleTo serving consumer needs an explicitly supported loader/profile
contract. Both event features need matched event-layout handling, the ordinary
history dispatcher and its actual recording wrapper before delivery. Raw source
facts and these helpers alone grant no route.
