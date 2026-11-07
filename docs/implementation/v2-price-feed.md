# Approved in-memory price feed

`pricefeedpolicy.Normalize` validates a feed definition and `BuildPlan` derives
the one bounded ID/currency/request plan from the selected compliance catalog.
`quotefeed.Service` implements `admission.QuoteProvider`: one background HTTP loop
publishes immutable observations in memory. `Capture` does no HTTP or SQL.
Valuation, unknown-price policy and monitor/enforce decisions remain in the real
financial Checker. The legacy V1 pricing service and SQL quote table are separate.

The definition retains `uri`, `refreshIntervalSeconds` (60–86,400) and
`format: coingecko-simple`, with optional `credential: {fromEnv: OPS_PRICE_FEED_*}`.
Only the named header credential may be bound at startup. There is no environment
URL/interval override, generic secret enumeration or HTTP caller-selected feed.
This library consumes a trusted normalized definition. Approved runtime-profile
compilation and exact source/plan/catalog pairing are required before production
mounting; library fixtures do not activate an existing runtime source profile.

## Provider response and freshness

The service requests exact configured IDs and currencies, forces
`include_last_updated_at=true`, and disables optional market-cap/volume/change
fields. It follows the [CoinGecko simple-price protocol](https://docs.coingecko.com/reference/simple-price).
Custom endpoints must supply the same timestamp-bearing shape, for example:

```json
{"ethereum":{"usd":2500.123,"eur":2300.456,"last_updated_at":1800000000}}
```

`FetchedAt` records successful response observation; `ProviderAsOf` preserves the
provider's integer timestamp. Missing, null, nonpositive, oversized or unavailable
prices never become zero or a fabricated current observation. Missing timestamps
produce no qualified prices; malformed/future timestamps reject the batch.
Unknown IDs/currencies, duplicate fields and trailing JSON reject the batch.
Failures and missing entries retain prior qualified observations with their
original timestamps. Refreshing memory does not extend their source age.

Each organisation applies its own maximum age through the existing Checker.
An interval equal to that maximum age leaves no room for provider age, HTTP
latency or scheduling jitter. Choose operational headroom; do not restamp old
quotes or weaken freshness to hide those windows. Cold startup has a valid empty
snapshot: approved unknown-price/monitor rules govern sends; issuing a travel
record still requires a positive qualified price.

## Bounds and credentials

The engineering limits are 512 unique IDs, five currencies, 100 IDs/request,
8,192-byte request URLs, 32 sequential requests/cycle, a one-MiB response and one
ten-second deadline across the complete cycle. Response work is bounded before
allocating decoded maps: string lexemes at most 604 encoded bytes, numeric
lexemes at most 128, depth at most eight, exact requested root IDs and at most
requested currencies plus one timestamp per object. No per-request fetch,
overlapping poll, SQL cache or retry loop is added.

Configured dynamic rows are planned even when enforcement is disabled, since
administrators may still prepare quotes/records. Implicit `ethereum` is added
only when an organisation has no native-token row. A present manual/native row
does not acquire that fallback. Unused feed plans cannot start a poller.

The service owns ID/currency/optional-flag query parameters. Names/symbol lookup,
reserved-key case variants, duplicate/case-colliding keys and known credential
query keys are rejected. `precision` accepts `full` or canonical 0–18. Other
approved nonsecret query values are preserved. Source authors must keep raw
credentials out of Git/URIs; rejecting known credential keys cannot detect every
possible secret. Query-only authentication needs migration to an explicit header
binding or a separately reviewed query-secret feature. No URI query, credential
or provider body is logged or included in public errors.

Default transport permits normal public HTTPS. Explicit trusted `AllowPrivate`
enables private HTTPS with normal certificate/hostname verification, and private
or loopback HTTP only. Actual resolved HTTP addresses must remain private; shared
metadata/link-local/unspecified denials apply in every mode. Default transport
uses no ambient proxy, TLS-verification bypass or redirects. An explicitly
injected transport/CA and the provider itself remain trusted data producers.
Source/quote digests identify observations; they do not prove market prices.

The common deny also includes the documented IPv6 metadata addresses for
[AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
and [Google Cloud](https://docs.cloud.google.com/compute/docs/metadata/overview),
even though they fall within otherwise permitted private IPv6 space. Literal
URL and resolved-address checks apply the same denial.

`Start` owns one loop: an immediate cycle, followed by the approved interval after
each cycle finishes. `Close` cancels current HTTP, waits for that loop and is
idempotent. It never closes a caller-owned transport. Previously captured
snapshots remain immutable. Normal context-honoring transport behavior is part
of the trusted adapter contract.
