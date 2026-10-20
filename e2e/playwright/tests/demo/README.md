# Demo acceptance E2E suite

This suite is the executable acceptance contract for the Open Privacy Suite
features used in demos. It runs the privacy proxy, chain indexer, admin UI, and
the privacy-mode block explorer together. It deliberately tests both positive
visibility and negative space: a scenario passes only when expected data is
present and protected data is absent from RPC, BFF JSON, and rendered UI.

The suite uses real Anvil transactions and Foundry contract bytecode. Mock auth
is limited to creating deterministic identities; authorization, disclosure,
indexing, redaction, compliance enforcement, and browser navigation use the
real product paths.

## Acceptance stories

| ID | Story | Executable oracle |
|---|---|---|
| RBAC-01 | As an org admin, I can give reader and writer groups different RPC methods and contract functions. | An allowlisted reader can call `count()` but receives an opaque 404 for `increment()`; the deployed counter state is exact. |
| RBAC-02 | As an org admin, I can restrict events independently from methods and grant one transaction with `visibleTo`. | A reader gets no receipt, the named observer gets exactly one expected log, and an outsider gets neither the hash nor participant address. |
| EXP-01 | As a transaction participant, I see consistent transaction details, labels, logs, and counters. | BFF list/detail/stats agree; the UI shows `Mine`, `My Org`, and `Logs (1)` for the real indexed transaction. |
| EXP-02 | As an ungranted or cross-org user, I cannot enumerate protected activity. | Detail returns the same opaque 404, the address page is restricted, search does not reveal the address/hash, and canary values are absent. |
| EXP-03 | As a reviewer, internal calls, mint transfers, and address counters stay exact. | A forwarded call produces one internal trace row, the mint shows one ERC-20 transfer, and address tabs/counts match the explorer APIs. |
| DISC-01 | As a full-disclosure auditor, I see the granted party's real identity and exact history. | Exactly one own and one disclosed address appear; grant history contains the expected transaction and no unrelated data. |
| DISC-02 | As a pseudonymous auditor, I see stable aliases but no real address or transaction hash. | The same `Address-*` appears in list, detail, history, and UI; protected addresses and hashes are absent. |
| DISC-03 | As a redacted auditor, I see timing-only history with uniform placeholders. | List, detail, transaction history, and UI use `[PRIVATE]`; real addresses, hashes, values, and unrelated rows do not leak. |
| DISC-04 | As an auditor, transaction-history and activity-log scopes are enforced independently of disclosure level. | Every level gets exactly one permitted transaction and the post-grant `eth_call` audit record; activity entries contain no addresses or parameters. |
| DISC-05 | As a user without a grant, I see no disclosed target. | Disclosure APIs return an exact empty array and the protected canaries are absent. |
| TR-01 | As a compliance admin, token transfers are valued using the configured token price and active currency. | 300 tokens at USD 2 are below a USD 1,000 threshold and are allowed. |
| TR-02 | As a compliance admin, changing currency revalues rather than reinterprets the token amount. | The same 300 tokens at EUR 4 become EUR 1,200 and are denied in enforce mode. |
| TR-03 | As a compliant sender, a matching travel-rule record permits the above-threshold transfer once. | A EUR 1,200 record allows the transfer and changes to `used`; amount and currency stay exact. |
| TR-04 | As an operator, monitor mode records a would-block decision without blocking the transaction. | The transfer succeeds and the compliance log contains the matching monitor decision. |
| VIEW-01 | As an org admin, the real **View as** button opens the explorer with only the target user's visibility. | The amber session survives explorer search/navigation, the protected contract is restricted, and stopping View-as restores admin visibility. |
| CONF-01 | As a privacy reviewer, explorer list, detail, metadata, search, and rendered views expose the same allowed set. | Exact field/value assertions plus canary scans detect over-disclosure, missing redaction, wrong labels, wrong log counts, and counter drift. |

The story IDs describe behavior rather than implementation. Add a new row and a
corresponding executable oracle whenever a demo starts relying on new behavior.

## Scenario model

`00-setup.spec.ts` creates two organizations and ten personas, builds groups,
assigns members, deploys `Counter`, `DemoERC20`, and `Forwarder`, configures
contract function/event grants, writes visible-to and forwarded transactions,
mines a mint transfer, approves all three disclosure levels, and configures
travel-rule prices. A versioned manifest shares those generated IDs between
Playwright projects. It lives only in the runner's `/tmp` because it contains
synthetic session tokens.

The feature specs run serially because later compliance stories intentionally
change configuration created by earlier stories. The suite has no retries:
privacy failures must not be hidden by a second attempt. `00-cleanup.spec.ts`
runs as the setup project's teardown and removes both organizations.

Protected addresses, transaction hashes, and calldata are registered as
canaries. Negative assertions scan raw proxy responses, BFF responses, search
results, and page text. Do not replace these with presence-only assertions.

## Run locally

Requirements: Docker, Docker Compose, Foundry, this repository, and a sibling
checkout of the explorer. The default explorer path is `../block-explorer`.

```bash
make demo-e2e
```

Use another checkout or worktree without modifying either repository:

```bash
make demo-e2e BLOCK_EXPLORER_PATH=/absolute/path/to/block-explorer
```

For browser debugging, keep the stack running:

```bash
make demo-e2e-debug BLOCK_EXPLORER_PATH=/absolute/path/to/block-explorer
make demo-e2e-down BLOCK_EXPLORER_PATH=/absolute/path/to/block-explorer
```

Reports are written to `e2e/playwright/playwright-report/` and raw traces,
screenshots, videos, and JUnit XML to `e2e/playwright/test-results/`. The startup
log records proxy, explorer, and indexer revisions so a failure is reproducible.

## Maintenance rules

- Drive user-critical navigation through the UI where the story names a UI
  action; use APIs for deterministic setup and exact response-shape oracles.
- Assert exact counts and identities, then assert forbidden canaries are absent.
- Cover same-org denial and cross-org denial separately even when both are 404.
- Never skip because a service or fixture is missing. Readiness and setup
  failures are suite failures.
- Keep selectors role-, label-, or title-based. Add test IDs only when the user
  interface has no stable semantic locator.
- Keep fixture values synthetic and credentials confined to the isolated test
  stack. Do not upload the scenario manifest as an artifact.
- When a mismatch appears between RPC and explorer, fix the leaking or missing
  product path; do not normalize the difference in the test.
