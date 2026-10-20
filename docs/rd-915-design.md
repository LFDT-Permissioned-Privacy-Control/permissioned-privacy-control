# RD-915 — runtime tracing for `eth_call`: design decisions

Compiled 2026-05-07.

Sister of `docs/rd-855-behavioral-shifts.md` — the precedent for per-ticket design rationale.

## Problem (one paragraph)

Today the proxy traces every internal CALL/STATICCALL/DELEGATECALL frame on the **send side** (`eth_sendTransaction`, `eth_sendRawTransaction`) and denies any frame whose target sits in another org without a grant. The **read side** (`eth_call`) only checks the entry-point address; once the entry contract is approved, anything its bytecode does internally is invisible to the proxy. In privacy-mode this lets an attacker in org A read org B's private state by composing a same-org wrapper contract that internally `STATICCALL`s into the org-B private contract and bubbles the result up via the return value. Read-only, but information leakage across org boundaries is exactly the threat the proxy must stop. Issue: RD-915.

## Cross-check verdict: fix the docs, not the requirements

Audit of `site/`, `docs/OPEN_ITEMS.md`, `REDACTION_SPEC.md`, and code comments found **the docs already over-promise current behaviour**:

- `site/src/app/docs/configuration/page.mdx`: "*All internal CALL/DELEGATECALL/STATICCALL targets are validated against RBAC permissions*" — false today; true after RD-915.
- `site/src/app/docs/security/page.mdx:553` (multicall row): "*Mitigated by runtime tracing (all calls validated regardless of target)*" — true for sends only today.
- `site/src/app/docs/troubleshooting/page.mdx:6`: "*all internal calls are validated regardless of target address*" — silently scoped to writes today.
- `REDACTION_SPEC.md` §3.7: silent on the read-side internal-call gap; documents response-side filtering only.
- `docs/OPEN_ITEMS.md` §4b: covers the *response-decoding* angle on `eth_call`. RD-915 is a different angle (internal-call tracing) and was missing — needs a new §4d entry.

**Decision:** RD-915 implementation is aligned with documented intent. No requirements adjustment needed; the docs are the artifact lagging the spec. Fix them in the same PR.

No prior design rationale was found anywhere for **why** `eth_call` was excluded from tracing. Best read: the original send-side tracer was scoped tight to deploys + mutating calls because that's where the chain-state risk lives, and the read-side leak via composability got missed. This doc is the rationale, going forward.

## Middle-ground decisions (Plan agent vs security review)

The architect proposed a 7-step plan; the security review pushed back hard on three items, lightly on three others, and confirmed two as fine. Recorded below in the form `[KEY DECISION]: chosen | rejected alternative | why`.

### KD-1 — Architect's `pure_helpers` skip-list is rejected as proposed

**Rejected:** address-keyed `pure_helpers(address, name, created_at)` table mirroring `shared_infrastructure`.

**Adopted:** **bytecode-hash-pinned** tag, `pure_helpers(address, codehash, name, attested_by, attested_at, reason)`, plus three constraints enforced in `TraceValidator`:

1. At validation time, fetch `eth_getCode(addr, "latest")`, keccak it, compare to stored `codehash`. Mismatch → treat the contract as untagged (do trace).
2. **Reject DELEGATECALL frames into `pure_helpers` regardless of tag.** Only `STATICCALL` and `CALL` with `value=0` are eligible to skip. DELEGATECALL gives the helper the *caller's* storage — it's a privilege-escalation primitive; no skip allowed.
3. Tag/untag operations append to `audit_log` with admin DID + reason. Non-negotiable for ISO 27001 A.5.15 / A.8.2.

**Why:** an address-only tag is a footgun — operator points an EIP-1967 proxy at a `pure_helper` address, the bytecode rotates under a stable address, and the skip persists silently. Vanta will flag any "operator can disable a control by INSERTing a row" as a missing change-management boundary. Codehash-pinning + DELEGATECALL exclusion + audit log close the abuse paths without losing the legitimate use-case (a known-pure utility contract).

### KD-2 — `from` spoofing on the read side is closed at the proxy boundary

**Adopted:** `validateEthCallWithTracing` rebinds `from` to the JWT-bound EOA before forwarding to `debug_traceCall`. Any user-supplied `from` that doesn't match the user's bound key is rejected with `400 invalid from`.

**Why:** the send side is implicitly safe — signed txes pin `msg.sender` to the unlocked key. The read side is not. If we forward `from` verbatim, an attacker JWT'd into orgA can call a same-org wrapper with `from = orgB-router-address`, hitting `if (msg.sender == orgB-router) { staticcall(orgB-secret) }` branches. `ValidateTrace` would still deny when the STATICCALL target is the orgB private contract, but only **if** that contract is actually registered to orgB; if the wrapper does the cross-org read via a `pure_helper` the attacker bypasses both checks. Forcing `from` to the JWT identity removes the foothold.

### KD-3 — Deny path messages are constants; address goes to access_logs, not the response body

**Adopted:** four fixed user-facing strings, no `%v` interpolation of upstream errors:

- `"call denied: cross-org access not permitted"` (RBAC verdict)
- `"call denied: trace depth exceeded; not provable as same-org"` (depth bound)
- `"call denied: tracing temporarily unavailable"` (upstream node error or timeout)
- `"call denied: invalid request shape"` (input validation, IsHexAddress)

The denied address goes into `access_logs.denial_address` (new column) and into `slog.Debug`, never into the response. **Why:** echoing `0xORG-B-CONTRACT` in the deny message tells the attacker an address they didn't otherwise know exists in another org — the same disclosure shape as RD-916. Don't reintroduce that surface here.

### KD-4 — `access_logs.denial_reason` enum (audit-of-the-audit)

**Adopted:** new column `denial_reason` (enum: `rbac_denied | trace_cross_org | trace_depth | trace_upstream_error | compliance | rate_limit | invalid_request`). Populate at every `logAccess` call site that writes a non-2xx status.

**Why:** today, `access_logs` collapses every cross-org denial into the same row shape (`status_code=403`, `method=eth_call`). A Vanta auditor running "show me Q3 cross-org denials" cannot tell `eth_call` cross-org from `eth_sendTransaction` cross-org from a plain RBAC method-not-allowed. ISO 27001 A.5.25 / A.8.16 wants distinguishable evidence per control.

### KD-5 — Env flag, default ON, for change-management rollback only

**Architect:** "no env flag, unconditionally on; gated by `RUNTIME_TRACING_ENABLED`."

**Adopted (compromise):** new env `RUNTIME_TRACING_ETH_CALL_ENABLED` (default `true`). If `RUNTIME_TRACING_ENABLED=false` the new flag is moot. If both are true (default), eth_call tracing is on. Operators can flip the new flag to `false` to disable just eth_call tracing in case of a sev-1 perf regression in production, without disabling all runtime tracing.

**Why:** the architect's "single switch" framing is right *operationally* — privacy-mode is the only mode and the protection should be on by default everywhere. But ISO 27001 A.8.32 ("change management") and the company's incident-response posture want a discrete, document-able rollback control. Default-true preserves the "unconditionally on" requirement of the issue; the flag exists for the rollback path, not for staged rollout. Document this explicitly in `site/src/app/docs/configuration/page.mdx`.

### KD-6 — Symmetry claim is downgraded: it's an open gap, not a closed one

**Architect's claim:** `GetBatchVisibility` already symmetrically denies cross-org log access for the scenario eth_call now denies; only need a regression test.

**Reality found in `internal/explorer/redactor.go:976-1060`:** `redactLogData` walks ABI-decoded **non-indexed parameters** of a log and zeros only `abi.AddressTy` slots whose visibility is not `VisibilityFull`. Opaque `uint256` / `bytes32` / `bytes` payloads are NOT redacted, even when the emitter is orgA and the value originated from a STATICCALL into orgB.

A contract pattern like `function leak(address t) external { (bool ok, bytes memory r) = t.staticcall(...); emit Snapshot(r); }` emits `Snapshot(bytes)` from orgA. The redactor sees emitter = orgA, allowed for the orgA viewer, returns the orgB-derived bytes in the clear.

**Adopted:** RD-915 closes this on the `eth_call` API path (the call is denied before any return value reaches the client). It does NOT close the explorer log path. The right move:

1. Land RD-915 as the read-side fix only.
2. Add a **failing** symmetry test in `e2e/access_visibility_symmetry_test.go::TestAccessVisibilitySymmetry` and `internal/server/explorer_redactor_wiring_integration_test.go::TestExplorerRedactorWiring_FullStack` that reproduces the bytes-payload leak. Mark it `t.Skip("RD-9xx — log-data full-redaction for cross-org-touched txs")`. Open the follow-up ticket.
3. Document the gap in `REDACTION_SPEC.md` as item §4d's twin: "explorer log payload is not redacted for cross-org-touched txs."

**Why:** the architect's symmetry claim was load-bearing per CLAUDE.md and turned out to be partly false. Better to ship RD-915 with the gap explicitly documented + a skipped test that becomes the regression net the day the follow-up lands, than to ship with a falsely-passing symmetry assertion.

### KD-7 — Sequencing inverted: regression test ships first

**Architect:** land helper extraction → `TraceTransactionUncached` → `pure_helpers` → validator rule → `validateEthCallWithTracing` (this is the user-facing change) → symmetry tests → proxy-upgrade regression test (last).

**Adopted:** the proxy-upgrade regression test (`e2e/eth_call_proxy_upgrade_test.go`) lands **first**, in skipped form, asserting that *if* eth_call tracing existed, an upgrade-then-call sequence would deny the second call. Then the same PR that lands `validateEthCallWithTracing` un-skips it. Plus: the test must inject a counting `TraceCache` mock that asserts `Get/Set` are NEVER called on the eth_call code path — so a future "let's add a perf cache" change fails the regression net, not just a behaviour-drift one.

**Why:** the architect's order ships the user-facing trace check before the regression net. Anyone who notices a perf regression in the four-week gap before step 7 lands could re-introduce input-keyed caching unchallenged.

**Post-implementation note (2026-05-08):** the "land skipped first" sequencing was not adopted in the merged PR. The regression net is delivered in two places that together cover the same surface:

- `internal/tracer/runtime_tracer_test.go` — `TestTraceTransactionUncached_BypassesCachedHit` and `_DoesNotPopulateCache` pin the cache-bypass at the tracer layer (a future `useCache=true` regression breaks these).
- `internal/server/eth_call_tracing_integration_test.go` — `TestEthCallTracing_ProxyImplementationFlip` exercises the same `(from,to,data,value)` twice with different upstream traces and asserts the second decision is fresh (a future cache-introducing regression breaks this end-to-end).

The counting `TraceCache` mock is not used; the same guarantee is delivered by asserting upstream-hit count on the scripted httptest server. No `e2e/eth_call_proxy_upgrade_test.go` file exists — references to it elsewhere in this doc are historical.

## Items the architect got right (move on)

- Helper extraction `runTraceAndValidate` from the three duplicate blocks in `jsonrpc_processor.go` (send / raw / debug). DRY beats blast-radius risk; the existing tests pin the send path.
- Explicit `RuntimeTracer.TraceTransactionUncached` instead of a `useCache bool`. Makes cache-bypass intent legible at every call site.
- Reuse `tracer.extractCallTargets`'s existing `maxTraceDepth=256` constant. Don't fork two depth limits.
- Treating eth_call traces as identical in shape to send traces (true; `ValidateTrace` doesn't care about signing).
- Reusing `TraceValidator.ValidateTrace` directly — the issue's reference to `factoryCallValidator` is stale; the live code is `internal/rbac/trace_validator.go`.

## Items added by security review that the architect missed

- **Per-call timeout for eth_call** distinct from the 30s send-side budget. 5s recommended. Caps individual trace duration on the read path. *Note (2026-05-08):* the original framing claimed this also prevented filling the concurrency-limiter quota for a JWT. That claim was wrong — the limiter is acquired *after* the trace runs (`jsonrpc_processor.go:460`), so the timeout caps a single trace's duration but not how many concurrent traces a single JWT may pin. Tracked separately as RD-923 (orthogonal to the cross-org isolation logic).
- **Input validation**: `IsHexAddress` on `to` and `from` *before* trace, so a malformed request doesn't burn a concurrency slot.
- **`eth_estimateGas` is a sibling read RPC that runs the EVM** and can leak the same state (revert reasons, SLOAD-derived branches). RD-915 must either include it or explicitly defer with a follow-up ticket. **Decision: defer — tracked as RD-924.** Including it doubles the PR scope and the threat shape is identical, so the follow-up is mechanical.

## Implementation order (final)

This PR (V1) ships the core feature plus the regression net plus the doc-update sweep. Steps 4–6 (`pure_helpers` schema + admin endpoints), step 8 (`access_logs.denial_reason` enum), and step 9 (failing-skipped symmetry test) are deliberately **deferred to follow-up tickets** — the security-sensitive `pure_helpers` admin surface and the `access_logs` schema change each deserve their own focused review and would dilute this PR.

V1 (this PR):

1. Add cache-bypass regression net in `internal/tracer/runtime_tracer_test.go` (`TestTraceTransactionUncached_BypassesCachedHit`, `_DoesNotPopulateCache`). The `e2e/eth_call_proxy_upgrade_test.go` file in earlier drafts of this plan was never created; the same guarantee is delivered at the tracer layer (above) and at the wrapper layer in `internal/server/eth_call_tracing_integration_test.go` (`TestEthCallTracing_ProxyImplementationFlip`).
2. Refactor `jsonrpc_processor.go`: extract `runTraceAndValidate` shared helper. Pin send-path behaviour with new tests *before* the refactor. Land + green.
3. Add `RuntimeTracer.TraceTransactionUncached`. Land + unit test.
7. `validateEthCallWithTracing` + wire into `Process` for `eth_call`. Forces `from := jwtBoundEOA`. New env flag `RUNTIME_TRACING_ETH_CALL_ENABLED` (default true). New ProcessError types with constant messages (no `%v`). 5s timeout for tracing. `IsHexAddress` validation pre-trace. Land + unit + integration cross-org tests (`internal/server/eth_call_tracing_integration_test.go`).
10. Doc updates: new `OPEN_ITEMS.md` §4d; fix the over-promise in three site/ pages; add `REDACTION_SPEC.md` paragraph on read-side tracing. Land.

Deferred (file follow-up tickets in same session):

- **`pure_helpers`** (steps 4-6) — net-new admin surface. Without it, every contract is traced; that's the safe-by-default fallback. Operators can request the skip-list when they have a use case.
- **`access_logs.denial_reason` + `denial_address`** (step 8) — auditability improvement, not load-bearing. Currently every denial collapses to `403/method=eth_call`; auditors can still distinguish by `method` until this lands.
- **Cross-org-touched log-data redaction symmetry** (step 9) — the spec gap that the security review surfaced. The eth_call API path is closed by V1; the explorer log-data leak via `bytes` payloads remains until the follow-up.

Each step in V1 is independently revertible. The user-visible behavior change is only step 7.

## PR security-review block (the items the merging reviewer must verify)

- [ ] eth_call denial returns 403, never 200-with-error.
- [ ] Deny response body never contains a non-precompile hex address.
- [ ] `pure_helpers` admin endpoints require tier-2 org admin or super-admin; cross-org tag attempts return 403.
- [ ] Migration 048 is `CREATE TABLE` only.
- [ ] `access_logs.denial_reason` is populated for every new denial path; existing rows are not back-filled (expand-only).
- [ ] DELEGATECALL frames into `pure_helpers` are denied even when the contract is tagged.
- [ ] `from` rebind is in place; user-supplied `from` cannot point at someone else's address.
- [ ] No `TraceCache.Get/Set` call on the eth_call code path (counting-mock assertion in proxy-upgrade test).
- [ ] `RUNTIME_TRACING_ETH_CALL_ENABLED` defaults to `true`; rollback path documented.
- [ ] `eth_estimateGas` follow-up ticket filed and linked in the PR description.

## Doc updates needed in this PR

| File | Change |
|---|---|
| `docs/OPEN_ITEMS.md` | Add §4d "eth_call internal-call tracing for cross-org isolation — RESOLVED by RD-915". |
| `REDACTION_SPEC.md` | New paragraph in §3.7: read-side tracing scope; explicit note that explorer log-data redaction does NOT yet cover cross-org-touched-tx leakage (link to follow-up ticket). |
| `site/src/app/docs/configuration/page.mdx` | Statement "*All internal CALL/DELEGATECALL/STATICCALL targets are validated*" is now true; add the env flag `RUNTIME_TRACING_ETH_CALL_ENABLED` to the configuration matrix. |
| `site/src/app/docs/security/page.mdx:553` | Multicall mitigation copy reads correctly post-RD-915. Remove the "(write methods only)" caveat that should be added pre-RD-915. |
| `site/src/app/docs/troubleshooting/page.mdx:6` | Statement reads correctly; add a note on eth_call deny error messages and how to interpret each of the four. |

## Open questions

- **`eth_estimateGas`**: file follow-up ticket immediately so it doesn't slip. Architecturally identical; PR scope discipline says defer.
- **Upgrade signal for tagged contracts**: when an operator tags a `pure_helper` and someone later upgrades the bytecode, the codehash check denies subsequent traces but the operator gets no notification. Add a daily "tagged contracts whose codehash drifted in the last 24h" report to the audit log? Out of scope for RD-915 but on the roadmap.

## Post-merge security review findings (resolved in follow-up commit)

A second-pass review surfaced six gaps in the V1 implementation. All are closed by the follow-up commit on this branch:

- **F1 — alias bypass.** `validateEthCallWithTracing` was gated on the literal string `req.Method != "eth_call"`. RBAC's entry-point check already resolves chain-specific aliases (via `ResolveMethodAlias`), so a method like `linea_call` aliased to `eth_call` passed RBAC but skipped tracing. Fixed: gate now uses `rbac.ResolveMethodAlias(req.Method) != "eth_call"`.

  **Important caveat — wildcard-passthrough methods are still untraceable.** A method that matches a wildcard prefix without an explicit alias has no defined param shape from the proxy's POV: we don't know how to extract `from`/`to`/`data`, and we don't even know whether the method runs the EVM (it could be a simple state query, an account-abstraction RPC, or anything else). Tracing such a method is impossible — the proxy literally cannot construct a `debug_traceCall` for it. Operators who turn on a wildcard namespace (`v2` config with a `wildcard.prefix` block) are accepting that **all** methods matching that prefix bypass RBAC AND cross-org isolation tracing. If cross-org isolation matters for a chain-specific method, register it explicitly with an `alias` entry instead of relying on the wildcard. This is documented prominently in `site/src/app/docs/configuration` under "Important: eth_call tracing scope".
- **F2 — historical-block validation gap.** `TraceTransactionUncached` hardcoded `"latest"` as the block tag, so a request like `eth_call(txObj, "0x1234")` was *traced at latest* but *forwarded at the historical block*. A proxy contract re-targeted between the historical block and latest opened the time-shifted twin of the proxy-flip threat the cache-bypass already closes. Fixed: new helper `extractEthCallBlockParam` validates `params[1]` (string tag/hex or EIP-1898 object) and threads it through to the tracer. Malformed shapes 400 pre-trace; missing falls back to `"latest"`.
- **F3 — send-side error-text leak.** The pre-RD-915 send-side trace path (`validateWithTracing`, `validateRawTxWithTracing`) emitted `fmt.Sprintf("runtime trace failed: %v", err)` and similar — the same disclosure shape KD-3 closes on the read side. Fixed: new constants (`sendTraceDenyTracerError`, `sendTraceValidatorError`, plus `sendTraceDenyMessage(reason)`) replace every `%v` interpolation; deniedTarget and upstream-error text stay in `slog.Debug`.
- **F4 — Rule 2d vs 2e collapse.** The validator's user-facing `Reason` is a single opaque `ErrContractAccessDenied` (intentional, prevents address enumeration). But audit / SIEM / triage had no structured signal to tell "touched another org" from "touched no org" from "tried to deploy without the claim". Fixed: new `DenialKind` enum on `TraceValidationResult` (`foreign_org` / `unregistered` / `deploy_claim_missing` / `create_foreign_org`); plumbed into the slog.Debug detail and exposed via the deny-side logging. Response body remains opaque.
- **F5 — concurrency limiter sat below the trace.** The post-trace placement meant a single JWT could pin N concurrent upstream `debug_traceCall` connections before the limiter saw it. Fixed: moved the limiter acquire to right after the RBAC-allow decision in both `Process` and `processRawTransaction`, so the cap covers the trace itself. The 5s per-call timeout still caps individual cost; the limiter now caps aggregate.
- **F6 — no Prometheus label for trace denials.** `eth_call` cross-org denials silently flowed through `logAccess` without `recordRPCOutcome`, so on-call had no `rpc_outcomes_total{outcome="..."}` series to chart. Fixed: added `eth_call_trace_denied` and `send_trace_denied` outcome labels at the relevant deny sites.

**Allowlist of methods that go through eth_call tracing** (open question above) is now answered by F1: any method whose alias resolves to `eth_call` is traced. Methods inside a wildcard-passthrough namespace without an explicit alias are intentionally out of scope, matching RD-911.

## Super-admin runtime toggle (follow-up commit)

A second piece of the follow-up commit adds an in-memory runtime toggle for the `eth_call` tracing knob, gated behind a super-admin auth check.

- **Routes:** `GET /api/v1/admin/system/eth-call-tracing` (any admin can read), `POST /api/v1/admin/system/eth-call-tracing` (super-admin token only — `ADMIN_API_TOKEN`, the same token used for other system-wide endpoints). Routes live under a new `/admin/system` group that omits org-scoping middleware (this is a fleet setting, not per-org).
- **Effect:** in-memory only. A process restart re-arms the env value via `SetEthCallTracing`. The env var stays the durable change-management control (ISO 27001 A.8.32); the endpoint is an emergency-rollback lever.
- **State:** the processor holds an `atomic.Pointer[ethCallTracingState]` so the validator's hot path reads lock-free and toggles are visible on the very next call.
- **Audit:** every POST writes a row to `rbac_audit_log` (`resource_type = "system_setting"`, `resource_name = "eth_call_tracing"`) and, when configured, fires a SIEM event. The reason field is required (non-empty, ≤ 500 chars) and is recorded in `new_value`.
- **Threat:** the endpoint flips a security-critical control. Risk is bounded by (a) super-admin-only writes, (b) audit logging on every change, and (c) restart-safety — an attacker with a stolen super-admin token can't durably disable tracing without ALSO breaking change-management (env edit + redeploy) which is the separately-audited path. The reverse threat (turning tracing back ON) has no exploit value.
