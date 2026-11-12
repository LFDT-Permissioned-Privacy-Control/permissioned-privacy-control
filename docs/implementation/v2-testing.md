# Native V2 regression checks

The native checks complement the repository's general Go/frontend CI. Retaining
a V1 test does not establish coverage of a rewritten V2 path. The native image,
browser entry and explicit integration controls must also be selected.

## Run the selected checks

Use the Go toolchain in `go.mod`, Node 24.22.1 and a working Docker daemon:

```sh
npm ci --prefix frontend
npm ci --prefix e2e/playwright
npm ci --prefix tools/v2-test-wallet --ignore-scripts
./e2e/playwright/node_modules/.bin/playwright install --with-deps chromium
docker pull postgres:16-alpine
node scripts/v2-test-prerequisites.mjs
OPS_TEST_BROWSER_CHANNEL=chromium node scripts/test-v2.mjs all
```

The runner supports `core`, `identity` and `browser` separately. It records
results in `.tmp/v2-test-results/` and fails if any required named case is
missing, skipped or unsuccessful. `core` covers the ten native commands,
architecture boundaries, policy evaluation, immutable configuration and pure
identity verification. It does not replace the operational adapter and RPC
tests included in the general `go test ./internal/...` job.

`identity` uses the pinned SDK to issue a synthetic role credential and generate
real AuthV2/SigV2 proofs. It checks the actual native broker, restricted SQL
stores, Core group mapping, fresh renewal and rejection of saved evidence after
identity-state replacement. `browser` adds central production assets and
two-tab session controls using Playwright. Its Azure identity provider and the
Privado identity-state contract are owned protocol fixtures, not hosted-provider
qualification.

The test wallet is separate from the application dependency graph. It uses new
public test keys and never opens an existing user's emulator identity files.
Ordinary integration tests explicitly disable the demo-persona mode.

## Public proving artifacts

The installer extracts only six manifest-selected files for AuthV2 and SigV2.
Each file must match its checked-in SHA-256 before it is installed, and every
test load checks those hashes again. The default directory is
`.tmp/v2-circuits/`, independent of a developer's home directory.

The official archive URL uses `latest.zip`. Its contents cannot silently change
the pinned test keys: a mismatch fails the setup. Availability can change, so
retain a verified cache or supply an HTTPS mirror using
`OPS_PRIVADO_CIRCUITS_ARCHIVE`. The same hashes apply to mirrors.
`OPS_PRIVADO_CIRCUITS_DIR` selects another cache root; the existing
`OPS_PRIVADO_AUTH_CIRCUITS` and `OPS_PRIVADO_SIG_CIRCUITS` overrides select exact
circuit directories. `OPS_PRIVADO_WALLET_MODULES` selects a separately installed
matching SDK dependency directory. No test downloads artifacts implicitly.

## Retained behavior and architecture coverage

| Contract | Representative V2 coverage |
| --- | --- |
| Transaction, receipt and log visibility | Shared `readprivacy` decision tests; native history, Explorer and actual indexer-shaped payload controls. |
| Nested execution and trace privacy | Client/mined trace HTTP, SQL and Recorder controls in `internal/activitylog`. |
| Wallet ownership | Signature/replay/concurrency/revocation/recovery controls in `internal/operational/walletsql`; revocation while output is held. |
| Guard v1 and submission | Existing `nodeapproval` controls plus native Guard bridge, both modes and post-broadcast error delivery. |
| Claims and groups | `internal/identity` source bindings, injected-group/stale-age negatives; actual broker login and renewal controls. |
| Git configuration | `policybundle` cold load, hashes, paths, profile isolation, bounded parsing and detached snapshots. |
| Durable output | Recorder ownership, exposure before response bytes, original deadline/cancellation after commit and recovery barriers. |
| Native perimeter | `internal/archtest`: no legacy server or optional EVM policy backend in the selected delivery. |

V2 intentionally replaces customer-consent disclosure administration and mutable
configuration/user-directory APIs. Their V1 tests still describe the legacy
delivery; V2 uses standing Git rules and operational checked/audited cases.
Partior captured participants and live `recordParty` rules are outside this
delivery. This checklist is not a percentage or an assertion-by-assertion
equivalence claim.

Hosted Microsoft tenant behavior, a particular physical wallet extension and a
deployed external role issuer require their respective environments. Local
cryptographic and browser fixtures do not establish those compatibility claims.
