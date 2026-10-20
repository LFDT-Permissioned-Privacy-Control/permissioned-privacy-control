# E2E invariant coverage audit

- **Audit date:** 2026-07-21 UTC
- **Branch:** `main`
- **Audited commit:** `9bcb6d901fff169b4b53c9ea1111b8f355ab38a7`
- **Repository:** `gateway-fm/open-privacy-suite` (formerly
  `gateway-fm/privacy-proxy`)

## Scope and method

This audit maps the repository's documented privacy, authorization, compliance,
deployment, and Docker-isolation invariants to the tests that actually gate
`main`.

For this report:

- **E2E** means a request crosses the externally exposed HTTP/RPC boundary and
  exercises production route registration plus the real backing components
  relevant to the assertion.
- A test that calls a redactor, access controller, filter helper, or database
  method directly is classified as a unit/integration test even if its filename
  or test name contains `e2e`.
- A reduced `httptest` router with hand-created tables is useful integration
  coverage, but is not deployed-stack E2E coverage.
- A test only counts as a `main` gate if the normal Make/CI invocation compiles
  and runs it.

This coverage classification is a static snapshot of latest `main` at the
audited commit above. Runtime harness validation for the implementation branch
is reported separately below. Green runtime lanes show that the covered paths
execute successfully; they do not add the missing assertions or erase the
missing invariant scenarios identified by this audit.

## Status in this implementation branch

This report remains a snapshot of the audited `main` commit above. The companion
changes on this branch address execution and host-safety prerequisites: the
regular Go CI step and the harness run both regular Go lanes (untagged and
`mockauth`); the complete harness also runs Playwright and the privacy boundary
suite with run-owned Docker identities and dynamic loopback ports, and adds
explicit chaos and soak modes. No new product-behavior or isolation-regression
test cases are added. The missing invariant scenarios in P0.2, the P0.3
isolation guard tests, the exact-oracle work in P0.4, and the P1 packs therefore
remain the prioritized coverage backlog.

### Measured runtime finding — production privacy audit DB wiring

The live harness run found that the production privacy Compose on latest main
lacks the audit-database bootstrap and `AUDIT_ADMIN_DATABASE_URL` /
`AUDIT_DATABASE_URL` settings required by the current proxy binary. The E2E-only
Compose overlay supplies those values and the initialization hook solely as a
test fixture so the topology can be measured. It does not modify or fix the
production manifest; the production deployment gap remains open.

## Executive conclusion

The repository has broad lower-level coverage, but it cannot currently claim
E2E enforcement of its stated invariants. Four issues dominate:

1. **Normal CI omits 51 security-oriented Go E2E tests.** Fifteen files require
   the `mockauth` build tag, while both Make and CI run without it.
2. **The explorer privacy/coherence contract has no deployed HTTP E2E.** The
   only `e2e/` explorer HTTP tests cover `viewable-addresses`; the five explicit
   row-survival/coherence invariants are covered by one reduced internal fixture.
3. **The normal Go E2E harness does not own an upstream chain.** It points at
   `localhost:8545`, and several positive tests accept `502 Bad Gateway` as a
   passing result. That proves an authorization gate was not observed, not that
   the intended RPC operation succeeded and was filtered correctly.
4. **Docker coexistence is not an enforced invariant and is currently unsafe
   for concurrent runs.** Fixed Compose project names, untrapped cleanup,
   daemon-wide prune, fixed privacy-test ports, and destructive shared-database
   fallback can affect another checkout or unrelated machine workloads.

The first implementation work should repair the gate and isolate Docker before
adding expensive scenario coverage. Otherwise new tests may still not run, or
may interfere with the machine they are intended to protect.

## Effective test inventory

| Lane | When it runs | Effective coverage | Material gap |
|---|---|---|---|
| Go `e2e/` in normal CI | Every PR/push to `main` | 31 top-level tests from 9 untagged files | 51 tests in 15 `mockauth` files are not compiled |
| Static privacy manifest tests | Inside the normal Go lane | Three raw-YAML checks for `docker-compose.privacy.yml` | No checks for `docker-compose.e2e.yml`, lifecycle commands, cleanup, or coexistence |
| Playwright Compose suite | Nightly, manual, or PRs carrying the `e2e` label | 89 normal `test(...)` declarations, all under `tests/ui`; 7 more are statically skipped and 1 is `fixme` | The configured `api` project selects zero files; this is not a normal required PR gate |
| Privacy-bypass runtime test | Weekly/manual workflow | One full privacy-topology network test | Fixed project/ports, a vacuous positive control, and generic host-port probes make the oracle unsafe/unreliable |
| `internal/...` tests | Every PR | Extensive redactor, handler, database, and security integration coverage | Does not prove deployed route/config/component wiring |

Evidence:

- `Makefile:186-188` and `.github/workflows/ci.yml:129-134` invoke
  `go test ./e2e/...` without `-tags mockauth`.
- `.github/workflows/e2e-playwright.yml:3-11,28-46` makes Playwright
  nightly/manual/label-gated rather than a normal PR gate.
- `e2e/playwright/playwright.config.ts:25-42` defines an API project for
  non-UI specs, but every current spec is under `e2e/playwright/tests/ui/`.
- `.github/workflows/privacy-bypass.yml:30-33,85-124` runs the network test on
  schedule/manual dispatch, not on ordinary PRs.

### Security E2E tests omitted by the default Go lane

These 15 files start with `//go:build mockauth` and contain 51 top-level tests:

- `e2e/access_control_test.go`
- `e2e/blocked_methods_test.go`
- `e2e/create2_test.go`
- `e2e/cross_org_isolation_test.go`
- `e2e/debug_trace_allowlist_test.go`
- `e2e/error_opaqueness_test.go`
- `e2e/input_validation_test.go`
- `e2e/membership_expiry_test.go`
- `e2e/method_access_test.go`
- `e2e/multi_org_users_test.go`
- `e2e/multicall_blocking_test.go`
- `e2e/rbac_contract_access_test.go`
- `e2e/rbac_writes_and_revocation_test.go`
- `e2e/receipt_log_entitlement_rd1183_test.go`
- `e2e/verbose_errors_test.go`

This is not merely missing future coverage: tests intended to protect cross-org
isolation, immediate revocation, method/function enforcement, receipt-log
entitlement, runtime tracing, request validation, and opaque errors already
exist but do not gate `main`.

## Prioritized findings

Severity meanings:

- **P0:** fix before relying on the E2E signal or running the Docker suite on a
  shared developer machine.
- **P1:** high-value invariant gap that can allow a privacy/security regression
  through while lower-level tests remain green.
- **P2:** important hardening, completeness, or test-quality gap.

### P0.1 — Restore the missing Go E2E gate

Add a required lane equivalent to:

```sh
go test -tags mockauth ./e2e/... -v -race -p 1
```

Keep an untagged production-build lane as well; the goal is not to replace the
production compile check with a dev-only binary. Add a discovery guard so CI
fails if the expected security suites disappear from the compiled test list.
With the current tree, the `mockauth` invocation should include 82 top-level
tests (31 untagged plus 51 tagged); the separately tagged privacy-bypass test
remains its own lane.

### P0.2 — Add deployed explorer coherence and count-leak E2E

The explicit coherence contract is in
`site/src/app/docs/security/privacy-requirements/page.mdx:257-303`:

1. `/transactions` is a superset of `/transfers`.
2. List and by-hash endpoints agree on row survival.
3. A surviving parent transaction propagates to transfer, internal-transaction,
   and log feeds, subject to field/event gates.
4. Field rendering is independent from row survival.
5. Active disclosure-grant rows survive at all levels while rendering according
   to Full/Pseudonymous/Redacted semantics.

Current coverage is insufficient:

- `e2e/explorer_test.go:95-245` only exercises
  `/api/v1/explorer/viewable-addresses`.
- `internal/server/explorer_coherence_e2e_test.go:80-97` manually registers five
  routes on a reduced Gin router, and its single test at line 142 covers only
  the admin-positive fixture.
- The specification itself lists seven required coherence fixtures at
  `REDACTION_SPEC.md:516-528`; the non-admin, disclosure-level, and genuine
  per-transaction `visibleTo` cases are not all driven through HTTP together.
- `docker-compose.e2e.yml:10-145` has Postgres, Anvil, backend, frontend, and
  Playwright, but no chain-indexer/explorer data source able to populate and
  query the chain-data surfaces.

Required E2E matrix:

- viewers: participant, same-org grant holder, same-org ungranted user, org
  admin, cross-org user, anonymous user, Full/Pseudonymous/Redacted disclosure
  grantee, `visibleTo` recipient, and impersonated target;
- surfaces: transaction list, by-hash, transfers, internal transactions, logs,
  blocks, tokens/holders, stats/charts, and paginated totals;
- assertions: exact row set, exact field substitutions, exact status for hidden
  by-hash rows, raw-body non-occurrence of forbidden addresses/hashes, and
  filtered rather than raw totals.

### P0.3 — Make Docker coexistence an enforced invariant

The Compose manifest has a good baseline: `docker-compose.e2e.yml` publishes no
host ports, has no fixed `container_name`, and declares project-scoped networks
and volumes. The lifecycle around it defeats that isolation:

- `Makefile:200-227` hard-codes `-p privacy-proxy-e2e`. Concurrent runs and
  checkouts share containers, network, and the named Postgres volume; either
  run's `down -v`/`e2e-clean` can stop and delete the other's state.
- `Makefile:207-212` has no `EXIT`/`INT`/`TERM` trap. A partial `up` failure or CI
  cancellation can leak resources; a failed `down` can be masked by the saved
  test status. Normal teardown also omits `--remove-orphans`.
- `README.md:118-136` bypasses the Make wrapper and omits `-p`. From the
  canonical `privacy-proxy` directory those commands share the default project
  with the dev stack and overlapping service names.
- `Makefile:253-256` runs daemon-wide `docker system prune -f`. This can remove
  unrelated stopped containers, unused networks, dangling images, and build
  cache and is directly incompatible with the coexistence goal.
- `e2e/privacy_bypass_test.go:102-115,248-257` hard-codes project
  `privacy-bypass-test` and public ports 8080/5173/3001. Concurrent checkouts or
  unrelated listeners collide.
- `e2e/privacy_bypass_test.go:176-180,336-348` tests generic host ports rather
  than Docker bindings owned by the project. Its own public proxy defaults to
  host 8080 while `block-explorer-api` is catalogued as an internal service on
  port 8080 (`deployments/privacy/trust-zone.yaml:54-70`), making that generic
  negative probe self-contradictory.
- The cross-zone positive control only logs a warning on failure
  (`e2e/privacy_bypass_test.go:297-333`), so the negative result can pass when
  the probe or target is broken.
- If a PostgreSQL testcontainer cannot start,
  `internal/db/test_helper.go:166-215` silently falls back to
  `localhost:5432/privacy_proxy_test`. `ResetTestDatabase` then deletes rows
  across the schema (`internal/db/test_helper.go:100-161`). Two checkouts can
  erase each other's state, and an explicitly supplied `TEST_DATABASE_URL` has
  no database-name/ownership guard.
- `internal/testutil/anvil.go:20-24` accepts a shared `ANVIL_URL` with no reset;
  `e2e/proxy_test.go:145-147` otherwise points ordinary tests at the machine's
  `localhost:8545` rather than an owned node.

Missing Docker isolation tests:

1. A fast manifest guard for `docker-compose.e2e.yml` rejecting host-published
   ports, fixed container/resource names, external/host networks, host PID/IPC,
   privileged mode, and Docker-socket mounts.
2. A lifecycle guard requiring a unique, overridable project ID and forbidding
   literal volume deletion and daemon-wide prune.
3. A gated runtime sentinel test that creates unrelated labelled
   container/network/volume resources, runs success and forced-failure paths,
   and proves the sentinels are byte-for-byte untouched.
4. A two-project concurrency test: start A and B, write distinct DB sentinels,
   tear down A, and prove B remains healthy with its data intact.
5. Partial-up and cancellation tests that leave zero resources carrying the
   test project label.
6. Privacy-bypass probes using dynamic public ports and container/network
   ownership inspection rather than assuming common host ports are globally
   unused.
7. Explicit opt-in plus ownership/database-name validation before any external
   PostgreSQL or Anvil endpoint may be used.

### P0.4 — Require an owned upstream and exact positive oracles

`e2e/proxy_test.go:105-211` starts the backend and PostgreSQL, but not Anvil. It
sets `NodeURL` to `http://localhost:8545`. Positive tests then accept an
unavailable upstream as success; for example `e2e/proxy_test.go:341-366` accepts
HTTP 200 or 502. Similar patterns appear in parameter/storage and tagged
grant/write tests.

The only Go E2E family that starts an owned Anvil and performs real deployment
and tracing is `e2e/create2_test.go:191-297`, and that file is currently omitted
by the missing `mockauth` tag.

For positive cases, require:

- an owned Anvil or deterministic network-boundary mock;
- an exact success status and JSON-RPC envelope;
- proof that the expected request reached (or deliberately did not reach) the
  upstream;
- postconditions on chain/database/audit state;
- no acceptance of 4xx/5xx merely because it was not the one denial code being
  targeted.

### P1 — Missing invariant scenario packs

| Invariant pack | Documented guarantee | Current highest coverage | Missing E2E |
|---|---|---|---|
| Access/visibility symmetry | Every `(viewer,address)` RPC decision agrees with explorer visibility (`REDACTION_SPEC.md:7-13`) | `e2e/access_visibility_symmetry_test.go:124-150` directly calls `AccessController` and the DB | HTTP RPC + explorer requests through real middleware/cache; EOA owner/non-owner, precompile, unregistered, expiry, disclosure, and impersonation rows |
| Cross-org + opaque denial | Foreign-org existence and resources cannot be inferred | Tagged Go HTTP tests plus internal tests | First make tagged tests run; then exact uniform status/body/timing-safe leak checks for every address-bearing method, nested call, list/count, and admin surface |
| Selective disclosure | Approval cannot widen scope; date/address scope, level, expiry, and revocation govern every surface | Internal service/handler tests; one UI form mutual-exclusivity spec | Request -> narrowed approval -> access workflow; in/out-of-scope rows, all levels, revocation/expiry, raw-body non-leak, counterparty lens, audit row |
| `visibleTo` | Parse top-level/embedded aliases, resolve addresses fail-closed, dedupe/cap at 32, strip before forwarding, persist, and enforce retrieval/unlock eligibility | `e2e/visible_to_test.go` directly calls DB/filter helpers; full receipt path exists only in an omitted tagged file | Actual send -> upstream capture -> stored visibility -> tx/receipt/log/explorer reads; unresolved address, 33 entries, cross-org, anonymous, method non-bypass, and post-revocation denial |
| Event logs | No ABI and unsafe dynamic payloads fail closed; anonymous topic 0 and all indexed/data addresses are scrubbed; participant status does not bypass safety gates | Internal RBAC/redactor/handler tests | Full RPC and explorer cases for ABI/no-ABI, dynamic opt-in per contract, anonymous event, participant/non-participant, receipt versus `eth_getLogs`, and `visibleTo` unlock |
| Block privacy | Both full/hash arrays and counts are viewer-filtered; aggregate leak fields are zeroed; block receipts drop non-participants | Internal response-filter tests | Authenticated real-block E2E for by-number/by-hash, both transaction modes, transaction-count methods, receipts, `logsBloom`, `gasUsed`, `blobGasUsed`, and `size` |
| `eth_call` tracing | Cross-org internal frames always deny; spoofed `from` denies; read traces are not cached across proxy target changes | Internal tracing integration tests | Real wrapper/proxy deployment, allowed same-org call, denied foreign internal call, target flip with identical calldata, spoofed sender, and runtime-toggle cases |
| Compliance | Every value transfer crosses sanctions/threshold/travel-rule checks; sanctions always block; monitor records `would_block`; missing price fails closed; records are single-use | Internal checker/server tests and UI config tests | Authenticated send with upstream-received/not-received oracle, enforce/monitor matrix, sanctions, price failure, atomic record reuse, audit/log verification |
| Admin/RBAC invariants | Admin flags are exclusive; org-admin claims are empty; method list is non-empty; tenant/operator scopes do not bleed | Internal API/DB tests and UI tests | Production-route API E2E for all three constraints, database constraint parity, cross-org admin reads/writes, cache invalidation, and audited mutations |
| Audit integrity | Real requests/mutations write the correct append-only, org-scoped chain | Internal DB/integration tests; E2E explicitly co-locates audit/main DB with owner credentials | Separate restricted audit DB, request -> row -> verify chain, mutation -> RBAC audit row, forbidden update/delete, and reveal-specific audit assertions |

### P2 — False-positive and maintenance risks

- `e2e/visible_to_test.go:243-314` names/comments a "logs only, not receipt"
  property but asserts that a listed viewer receives the receipt. The assertion
  matches current docs; the stale name/comment should be corrected before it is
  copied into new tests.
- `e2e/cross_org_isolation_test.go:164-179` describes an unregistered address as
  public/reachable even though `REDACTION_SPEC.md:78-89` says unregistered
  addresses are private by default. It only fails on 403, so the expected opaque
  404 can make this purported positive case pass.
- Several tagged positive tests reject only 403/404 and accept unrelated
  400/401/500 outcomes. The banned-write case can fail earlier at sender
  validation, never proving the ban gate.
- `e2e/proxy_test.go:134-143` binds the in-process server to `:0` on all
  interfaces; its ordinary cleanup at lines 204-209 does not stop the server.
- The Go E2E admin client relies on `ADMIN_API_TOKEN` being unset, so much of its
  setup does not exercise production admin authentication.
- Playwright fixture cleanup suppresses failures and shared bind-mounted
  report/result directories can be overwritten by concurrent runs.
- `README.md:110` claims a 131+ test full integration suite, but the configured
  API project has no specs and the present suite is UI-only. The manual examples
  also reference suites that no longer exist.
- `docker-compose.e2e.yml:6,19-21` calls `e2e-postgres-data` anonymous, but it is
  a named Compose volume.

## Specification conflicts to resolve before adding block assertions

New E2E tests should not encode an accidental choice between contradictory
documents:

- `site/src/app/docs/security/privacy-requirements/page.mdx:92-103` says block
  `gasUsed` and hash-only transaction arrays are always public.
- `site/src/app/docs/security/response-filtering/page.mdx:164-179` says hash-only
  arrays are participant-filtered and `gasUsed`, `blobGasUsed`, and `size` are
  always zeroed.
- `REDACTION_SPEC.md:208-218` agrees on zeroing aggregate gas/size but says
  hash-only arrays pass through.

Choose the intended contract, update all three documents, and then pin both RPC
and explorer behavior with exact E2E assertions.

## Recommended implementation sequence

1. **Host safety first.** Replace fixed project names with a unique,
   caller-overridable run ID; use a trap-based lifecycle wrapper; remove global
   prune/literal resource deletion; allocate or avoid host ports; forbid silent
   shared DB/node fallback. Add manifest, sentinel, and two-project tests.
2. **Restore the gate.** Add required untagged and `mockauth` Go lanes plus a
   compiled-test discovery guard. Make the Playwright/API invariant smoke pack a
   required PR check; leave the larger UI matrix nightly if runtime demands it.
3. **Create one owned invariant stack.** Use Anvil, backend, main Postgres,
   restricted audit Postgres, and a real indexer path. Provide deterministic
   helpers to mine transactions/logs, wait for indexing, create viewer grants,
   and query every surface.
4. **Land the P0 privacy matrix.** Cross-org/opaque denial, explorer coherence,
   counts/totals, exact field rendering, and revocation/cache invalidation.
5. **Land the P1 packs.** Disclosure/View-as, `visibleTo`, event safety, blocks,
   trace target changes, compliance, admin invariants, and audit integrity.
6. **Resolve documentation/test drift.** Fix the block contract and stale test
   comments/oracles, then make invariant docs link to the exact E2E case IDs.

## Exit criteria for the coverage effort

- Both untagged and `mockauth` Go E2E lanes are required and enumerate the
  expected suites.
- Every positive RPC assertion proves upstream execution and exact response;
  every negative assertion proves the intended gate and opaque payload.
- All five explorer coherence invariants pass for positive and negative viewer
  matrices against production route registration and indexed data.
- Counts, totals, charts, and pagination never reveal hidden rows.
- Two E2E stacks can run concurrently; tearing one down leaves the other and
  unrelated Docker resources untouched.
- Success, failure, partial-up, and cancellation leave no resources with the
  completed run's project label.
- No test uses an external database/node without explicit opt-in and verified
  per-run ownership.
- The Playwright `api` project contains and executes a non-zero invariant smoke
  suite on normal PRs.
- The privacy-bypass positive control is mandatory and all reachability checks
  are attributed to the intended project/container, not generic host ports.
