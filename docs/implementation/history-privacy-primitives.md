# History privacy primitives

History and Explorer privacy share pure decisions, ABI helpers and row renderers:

- `internal/readprivacy` contains the standard-library-only transaction and log decisions.
- `internal/explorerdata` contains data DTOs, visibility values and pseudonym helpers.
- `internal/readprivacyabi` contains the existing event-rule values and JSON states, param matching, indexed-self matching, calldata address detection and log field masks.
- `internal/explorerprivacy` contains the existing transaction, transfer, internal-frame, log and holder row/field rendering bodies.

The legacy `rbac` and `explorer` names alias or forward to these declarations. Their adapters still perform the existing database and resolver calls. The pure packages open no database connections, issue no queries and import no database driver, user-directory, network client or policy VM. Geth's number/address types retain their standard SQL conversion interfaces; those interfaces do not connect to a database.

`explorerprivacy.RedactBatch` accepts a bounded set of rows and resolved facts. Before rendering it checks that required visibility, event-rule, ABI, parent and exact transfer-log decisions are present. Missing context returns an error without a partial batch. It cannot establish that those facts came from an authentic, current source: the caller owns identity verification, current permissions, source qualification and the final delivery check. Input facts are trusted in-process values, never request-supplied permission assertions.

The legacy adapters use the extracted row primitives so their old lookup and error behavior remains unchanged. This includes the legacy no-resolver posture; the complete-batch entry point rejects that posture. Calldata participation is position-aligned with its input row, so duplicate hashes cannot borrow a sibling row's ABI result.

The renderers preserve the distinctions that affect privacy:

- Standard Explorer transaction rows can recognize a participant through actual from/to, supported calldata recipients, ABI-decoded address arguments or the accepted indexed-log participant signal. Strict transaction rows use actual from/to only.
- A transfer-participant union can keep a parent transaction row. Only a genuine transaction listing can reveal fields through the share paths; the union does not reveal sibling transfers or internal frames.
- Strict transfer rows require admission of their exact source log. Strict internal rows require participation in their parent transaction. A parent-party reveal promotes only the frame side that is itself a parent party.
- Non-Full embedded log addresses are zeroed and omitted from address-metadata keys. Hidden emitters are dropped before bypasses. Full payload unlock and the standard admin/no-ABI behavior retain their existing ordering; the helpers do not promise to decode arbitrary opaque bytes.
- The optional admin volume/value branch remains an explicit input. The pure renderer does not decide who may enable it. Strict ignores that branch.
- The event-rule fold preserves the existing constrained-first behavior for duplicate topics. An unconstrained alternative still dominates; two constrained alternatives are not silently changed into an OR.

Address ownership and permission lookup, RPC/REST block rendering, pagination, activity recording and protected disclosure source coverage remain the responsibility of their respective callers. Moving these primitives does not change those contracts.

The focused controls cover legacy/new-kernel parity, strict and standard behavior, listing versus transfer union, field and metadata masks, missing complete context, event-rule JSON states and the dependency boundaries.
