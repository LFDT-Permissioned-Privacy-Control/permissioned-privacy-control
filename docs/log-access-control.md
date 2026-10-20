# Log Access Control — Developer Reference

**Status:** RD-751 implemented, RD-753 documented. Pre-audit review.

---

## Architecture

Log filtering happens in two places in the request pipeline:

```
Client → Proxy → Node
                  ↓
              Response
                  ↓
          ┌───────────────────────┐
          │ jsonrpc_processor.go  │  Routes to method-specific filter
          └──────────┬────────────┘
                     │
        ┌────────────┴──────────────┐
        │                           │
   eth_getLogs              eth_getTransactionReceipt
        │                           │
   FilterLogsWithEventRules    FilterReceiptLogsWithEventRules
   (event_log_filter.go)       (event_log_filter.go)
        │                           │
        └────────────┬──────────────┘
                     │
           FilterEventLogs(logs, perms, userAddresses, abiProvider)
           (internal/rbac/event_filter.go)
```

### Entry Points

1. **`internal/server/jsonrpc_processor.go`** — Wires event log filtering into the
   response pipeline for `eth_getLogs` (line ~523) and `eth_getTransactionReceipt`
   (line ~513).

2. **`internal/server/event_log_filter.go`** — Adapts the JSON-RPC response structure
   for the core filtering function. `FilterLogsWithEventRules` handles `eth_getLogs`,
   `FilterReceiptLogsWithEventRules` handles receipts (participant check + log filtering).

3. **`internal/rbac/event_filter.go`** — Core filtering logic in `FilterEventLogs`.
   This is the single-pass filter that applies admin bypass, event rules, default
   address-based filtering, and param rule matching.

### ABI Provider

`storeABIProvider` (in `event_log_filter.go`) implements `rbac.ABIProvider` by looking
up contract ABIs from the RBAC store. It caches ABIs within a single request to avoid
repeated DB lookups. This is needed for param rule decoding when non-indexed parameters
are constrained with `"self"` rules.

---

## Filtering Algorithm

`FilterEventLogs` processes each log entry in a single pass:

```
for each log:
  1. Parse log JSON (address, topics, data)
  2. Get ContractAccess for log.address from EffectivePermissions
     → nil? Drop log (no access / cross-org isolation)
  3. Admin bypass: ClaimAdmin in access.Claims?
     → Yes: Include log unconditionally. Continue to next log.
  4. No event rules (access.EventRules == nil)?
     → Default mode: include if user's address appears in any topic
  5. Event rules configured:
     a. Empty topics? Drop (anonymous event blocked in allowlist mode)
     b. Match topic0 against rules
     c. For matching rules with param_rules: check "self" constraints
        (OR semantics across param rules within a rule)
     d. Include if any rule allows
```

### Admin Bypass (RD-751)

The admin bypass is checked immediately after contract access resolution, before
any event rule or address-based filtering. If `containsClaim(access.Claims, ClaimAdmin)`
is true, the log is included without further checks.

This covers:
- **Per-contract admin**: User's group has `admin` claim via `group_access.claims`
  and a `contract_grant` linking to the contract.
- **Org admin**: User is in a group with `is_org_admin = true`. The resolver
  (`computeOrgAdminPermissions`) grants `AllClaims()` (which includes `admin`)
  on every contract in the org.

Only the `admin` claim triggers the bypass. Users with `deploy` or `upgrade`
claims (but not `admin`) are subject to normal filtering — those are operational
claims (contract creation / proxy upgrade), not log-visibility grants.

---

## Event Rules Semantics

| `event_rules` value | Meaning |
|---------------------|---------|
| `null` (nil) | Default address-based filtering — log visible if user's address in any topic |
| `[]` (empty array) | Deny all events — no logs pass |
| `[{topic0: "0x...", name: "Transfer"}]` | Allowlist mode — only listed events pass |
| `[{topic0: "0x...", param_rules: [{index: 0, must_be: "self"}]}]` | Allowlist + constraint — event must match AND user's address must be in specified param position |

### Param Rule "self" Matching

For param rules with `must_be: "self"`:

1. **With ABI**: Determines if param is indexed (in topics) or non-indexed (in data).
   For indexed params, checks the corresponding topic slot. For non-indexed params,
   ABI-decodes the data field and checks the address.

2. **Without ABI**: Falls back to checking `topics[paramIndex + 1]`. This only works
   for indexed params. Non-indexed params without ABI fail closed (no match).

3. **OR semantics**: Multiple param rules on the same event use OR — if the user's
   address matches ANY constrained position, the log passes.

---

## Test Matrix Reference

Tests are in `internal/rbac/event_filter_test.go`. Key test groups:

### Admin Bypass Tests (RD-751)

| Test | Scenario | Expected |
|------|----------|----------|
| `TestFilterEventLogs_AdminClaim_Bypass` | Admin with restrictive event rules | All logs visible |
| `TestFilterEventLogs_OrgAdmin_Bypass` | Org admin, user address NOT in topics | All logs visible |
| `TestFilterEventLogs_AdminSeesAllLogs_NoAddressInTopics` | Admin, no event rules, no address in topics | All logs visible |
| `TestFilterEventLogs_AdminBypassWithEventRulesStillSeesAll` | Admin with allowlist, non-listed events | All logs visible |
| `TestFilterEventLogs_AdminBypassWithEmptyEventRules` | Admin with `[]` deny-all rules | All logs visible |
| `TestFilterEventLogs_AdminBypassWithAnonymousEvent` | Admin, anonymous event | Log visible |
| `TestFilterEventLogs_AdminOnOneContract_ReadOnAnother` | Admin on A, read on B | Bypass on A only |
| `TestFilterEventLogs_DeployWriteClaims_NoBypass` | deploy+write but no admin | Normal filtering |

### Non-Admin Filtering Tests

| Test | Scenario | Expected |
|------|----------|----------|
| `TestFilterEventLogs_ReadUser_NoAddressInTopics_Filtered` | Read user, no address in topics | Log hidden |
| `TestFilterEventLogs_ReadClaim_NoByppass` | Read + event rules | Only allowed events |
| `TestFilterEventLogs_NoEventRules_DefaultAddressFilter` | Nil rules, address in topic | Log visible |
| `TestFilterEventLogs_AllowlistMode` | Event rules, matching topic0 | Log visible |
| `TestFilterEventLogs_NilVsEmptyEventRules` | nil vs [] semantics | nil=address filter, []=deny all |

### Cross-Org Isolation Tests

| Test | Scenario | Expected |
|------|----------|----------|
| `TestFilterEventLogs_CrossOrgIsolation_NoAccessToOtherOrg` | No access to other org's contract | Log hidden |
| `TestFilterEventLogs_CrossOrg_NoAccess` | Contract not in ContractAccess | Log hidden |
| `TestFilterEventLogs_NoContractAccess` | Unknown contract address | Log hidden |

### Fail-Closed Tests

| Test | Scenario | Expected |
|------|----------|----------|
| `TestFilterEventLogs_NilPerms_FailClosed` | perms is nil | All logs denied |
| `TestFilterEventLogs_MalformedDataWithParamRules` | Truncated data field | Log hidden |
| `TestFilterEventLogs_ParamRuleIndexOutOfRange` | Param index 99 | Log hidden |
| `TestFilterEventLogs_NonIndexedParam_NoABI_FailClosed` | No ABI for non-indexed param | Log hidden |

---

## Edge Cases

### NULL ABI

When no ABI is registered for a contract and param rules reference non-indexed params,
`matchesParamSelf` cannot decode the data field. It falls back to checking
`topics[paramIndex + 1]`, which will not contain the non-indexed param data. Result:
param rule fails to match (fail-closed).

### Malformed Logs

Logs that fail JSON unmarshalling are silently skipped (dropped from results). This
is intentional — malformed data should not leak through the filter.

### Empty Topics Array

Logs with `topics: []` (anonymous events) are blocked in allowlist mode because there
is no topic0 to match. In default mode, the address-in-topic scan finds nothing.
Only the admin bypass includes them.

### Case Sensitivity

All address comparisons are case-insensitive. Addresses in topics, user addresses,
and contract addresses are lowercased before comparison.

---

## Running Tests

```bash
# Run all event filter tests
go test ./internal/rbac/ -run TestFilterEventLogs -v

# Run only admin bypass tests
go test ./internal/rbac/ -run "TestFilterEventLogs_Admin" -v

# Run the full rbac test suite
go test ./internal/rbac/ -v
```
