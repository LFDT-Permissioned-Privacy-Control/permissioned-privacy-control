# Approved compliance source and the shared checker

`catalog-compliance/v1` selects native-v2, identity and a required global
`complianceCatalog` file. Its closed schema is
`ops.compliance-policy/v1alpha1`, kind `CompliancePolicy`, with explicit
`organizations` and `sanctions` arrays. Every declared bundle organization has
exactly one entry containing `organizationId`, `spec`, `recordMaxSeconds` and
`priceMaxAgeSeconds`. The spec contains the existing settings, address thresholds
and token prices. Unknown fields, case aliases, duplicates, missing fields and
explicit nulls are rejected.

The default limits are 1 MiB, depth 32, 256 organizations, 4,096 threshold rows,
4,096 token-price rows and 4,096 sanctions, with a 1 MiB aggregate string budget.
Row budgets apply across organizations. Record duration is positive and at most
30 days; quote age is positive and at most 24 hours. Compilation copies the
organization index once and discards it. Catalog getters return detached values.
Raw file hashes and normalized semantic digests are separate identities.

The new source uses the same numeric and settings validators as the legacy
configuration documents: float64 decimal round-trip checks, exact threshold
cents and existing price bounds. The runtime still uses the existing float64
valuation algorithm. The new profile rejects configured token decimals above
77, which its existing conversion cannot execute; the legacy document validator
continues to accept its original range of 0 through 255.

Sanctions are explicit global or organization entries. A global or matching
organization entry applies; an organization entry cannot override a global hit.
These are approved source rows, not a live sanctions feed.

The profile is validation-only and rejects runtime and disclosure globals.
Preparation and cold loading share the same compiler, global-file count/path
checks and aggregate byte budget. Requirements describe dependencies, not
readiness. Quote capability is inferred for an enabled organization with a
configured CoinGecko ID or no native-token row. An existing manual native row
with no usable active-currency price remains unknown and does not fall through
to the implicit system quote.

`NewSourceChecker` uses the existing `compliance.Checker` and its transfer
detector, price precedence, thresholds, sanctions and record-claim algorithm.
Its narrow `CheckStore` has nine existing decision methods. It preserves a
concrete store's optional transaction-bound claim interface. The legacy
`NewChecker`, DTOs, constructors, settings fallback and preview behavior remain
available.

Source checker options capture one organization, canonical OPS ActorID,
explicit currency, UTC decision time and maximum quote age per request. The
caller must authenticate that actor separately. Check and preview verify the
request scope, then obtain and validate one configuration before the detector's
early return. A missing configuration never silently disables a source check.
The source path uses only an exact positive currency-map entry, with no scalar
USD fallback. System quote freshness uses the captured decision time, rejects
zero or future timestamps, and accepts the exact maximum-age boundary.

Every source audit-write failure returns a nil result and
`AuditUnavailableError`, also identifiable with `ErrAuditUnavailable`.
Operational callers must roll back record claims when this happens. The shared
checker does not itself make claim and audit operations one SQL transaction.
The source record-duration field constrains record issuance; it does not add
new expiry behavior to the existing checker.

Source preview requires the separate readonly `SourcePreviewStore` interface.
It writes no audit row and consumes no record. A bound record must still cover
the current actor, organization, beneficiary, token, amount and currency; its
original unused-record expiry does not invalidate an already used binding.
A mismatched binding cannot borrow another unused record, and renewal is
bound-only. A preview result is not authorization to send a transaction.

The retained detector checks one root transfer: native value or a recognized
direct ERC-20 `transfer`/`transferFrom`. Recognized ERC-20 calldata takes priority
over attached native value. Enabled detected transfers check spender, sender
and recipient sanctions before valuation; sanctions deny even in monitor mode.
This is not coverage of every zero-value call, both attached assets or all
internal transfers in a trace. Record claims, audit persistence, provider HTTP,
record APIs and send/report integration require their actual operational
adapters; this source library supplies none of them.
