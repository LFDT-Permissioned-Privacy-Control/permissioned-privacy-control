# Native V2 local walkthrough

`make demo-v2` builds and starts production native OPS, the V2 Explorer, a real
Reth application chain, the real chain indexer and creation observer. The separate
demo identity wallet creates real Privado proofs from explicitly public test
credentials and serves a controlled identity-state contract. It is not a hosted
Privado deployment. OPS uses its normal verification and login endpoints.

Use Node24, Docker with Compose/Buildx, and enough space for container builds.
Docker host networking must work: Linux and OrbStack support it; enable host
networking on Docker Desktop. All selected listeners use loopback and persisted
random ports. The launcher uses a separate Docker configuration for public
images and never reads registry credentials from macOS Keychain.

These local services are trusted test components. Cookies for `localhost` span
ports, so this walkthrough does not demonstrate cookie isolation between hosts.
The separate OPS/app/wallet origin tests are described in the testing guide.

```sh
make demo-v2
make demo-v2-status
make demo-v2-check
make demo-v2-down     # keep identities, chain, databases and configuration
make demo-v2-reset    # explicitly delete only this checkout's demo volumes
```

The first run downloads the pinned public proving circuits and exact dependency
revisions. A changed circuit fails its hash check. Explorer and indexer revisions
come from [the dependency lock](../../scripts/v2-demo/dependencies.json); a local
override must be the exact clean commit:

```sh
export OPS_V2_DEMO_EXPLORER_SOURCE=/absolute/path/to/ops-explorer
export OPS_V2_DEMO_INDEXER_SOURCE=/absolute/path/to/ops-indexer
make demo-v2-check
```

The check installs the locked Playwright package and Chromium, then drives the
actual built UI. Set `OPS_TEST_BROWSER_CHANNEL=chrome` to use an installed Chrome.
Source revisions must be available at their locked remote; no branch fallback or
silent test skip is used. Logs and selected public URLs live under
`.tmp/v2-demo/<project>/`. `OPS_V2_DEMO_PROJECT` can select another isolated demo.
Running `up` again reapplies the selected files and restarts serving processes;
it keeps the existing volumes and identities.

## Try the roles

Open the printed Explorer URL and select **Sign in**. On the OPS page choose
`demo-admin`, `demo-deployer`, `demo-reader` or `demo-outsider`. Expand
**Verification request** and copy its URL. Open the printed demo wallet URL in a
second tab, choose the matching persona, paste the original request URL and
generate its proof. Return to OPS, inspect the complete holder DID, choose
**Use this identity**, then **Continue to application**. Use separate browser
profiles/private windows to compare identities independently.

The generated certificate belongs only to this local demo. Accept the local
certificate warning for the printed URLs when browsing manually. The launcher
does not install a system-wide CA. Container clients trust only the selected CA
in their own process configuration; its private key stays offline.
The launcher uses browser-compatible P-256 TLS certificates. For missing,
mismatched or older demo TLS material, `scripts/v2-demo.sh repair-tls` repairs
only TLS files and restarts their consumers; identity keys and stored data stay
intact. Valid existing P-256 material is retained.

`make demo-v2-check` links the public demo wallets through actual ownership
challenge/sign/verify requests, deploys `DemoRecord` through OPS and submits a
fresh `set` transaction. It waits for the real receipt, nonempty runtime code,
indexer progress and the observer's actual creation association before comparing
views. Repeating the check keeps the existing deployment and submits a fresh
call. Its application artifact is compiled from
[DemoRecord.sol](../../scripts/v2-demo/DemoRecord.sol) with Solidity0.8.35;
execution policies remain native Go and no Solidity compiler is shipped.

The deployer sees its transaction. The admin sees the event's subject address;
the reader sees that subject masked and cannot retrieve the sender's transaction.
The outsider can authenticate but receives no organization/data permission.
The event subject is the admin's separately verified address, distinct from the
transaction sender. Event-entitled readers retain V1's receipt-envelope behavior:
receipt `from`/`to` may be visible. Masking one log parameter does not promise to
hide the receipt sender.

The wallets use **public test private keys**: scalar1 for admin,2 for deployer,
3 for reader,4 for outsider. Never fund them outside this isolated chain. The
demo wallet picker proves identity; it is not an Ethereum browser wallet.
Manual wallet linking can use a real browser wallet with the corresponding
public test account, while the check uses the same native API and EIP191 proof.

## Change the approved configuration

```sh
make demo-v2-revoke-reader
make demo-v2-restore-reader
```

Each command drains OPS, prepares a new immutable approved Core bundle, updates
the selected runtime pin and restarts the production server. The existing
identities, operational epochs, wallets, chain and index remain intact. The check
also verifies removal/restoration of the contract event read grant against the
existing authenticated reader; other method permissions remain configured. There is
no configuration watcher or SQL policy editor in this demo.

Serving containers receive only their own selected configuration, leaf TLS key
and restricted operational credentials. Offline bootstrap retains database-owner
credentials and the CA private key in a separate volume. Ordinary shutdown keeps
all owned state; cleanup rejects collisions with another checkout's resources.

For the other required automated controls, see [V2 testing](v2-testing.md).
