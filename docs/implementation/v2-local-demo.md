# Native V2 local walkthrough

This walkthrough shows a bank's file-based permissions, verified identities,
wallet ownership, contract execution, private Explorer views and a disclosure
that does not require customer approval. It uses production native OPS and
Explorer with a real Reth chain, indexer and creation observer. The separate
identity wallet produces real Privado proofs against a controlled test issuer
and identity-state service; it is not a hosted Privado deployment.

## Quick start with an existing installation

Run from this checkout's root:

```sh
make demo-v2-resume
make demo-v2-info
```

Resume uses existing images, installed dependencies and hash-checked circuits.
It retains identities, wallet links, configuration and chain data. Missing
prerequisites produce an error; this command does not build, download, reinstall
packages or reset the demo. Use it when disk space is limited.

Choose one way to run the complete scenario:

```sh
make demo-v2-walkthrough       # visible Chrome windows; press Enter at the end
# OR
make demo-v2-check-prepared    # same checks headlessly against the running demo
```

The visible walkthrough resumes the prepared stack, signs in four browser
contexts, links test wallets if necessary, deploys or reuses the contract and
submits a fresh transaction. It waits for the real indexer and observer, compares
permissions, shares a second transaction with Reader, opens a disclosure and
checks a configuration change. Each completed
action prints `PASS`. Actual transaction and disclosure links are printed at the
end, and the browser windows stay open until you press Enter in the terminal.
This is a finite functional walkthrough, not a load test.

Prepared commands use installed Chrome by default. An already installed
Playwright Chromium can be selected with `OPS_TEST_BROWSER_CHANNEL=chromium`.
They do not install a browser. `make demo-v2-check` performs initial setup and is
intended for a fresh installation or CI.

## The demo scenario

The organization is **Demo Bank** (`demo-bank`), ID
`11111111-1111-4111-8111-111111111111`.

| Identity | Verified external evidence | OPS group | What to show |
| --- | --- | --- | --- |
| `demo-admin` | Demo issuer's role 1 credential | Admin | Full event subject; authorized disclosure. |
| `demo-deployer` | Role 2 credential | Deployer | Linked wallet, signed deployment/call and own transaction. |
| `demo-reader` | Role 3 credential | Reader | Masked event subject, unavailable private transaction, signed write denied. |
| `demo-outsider` | Identity proof without a role credential | None | Authentication succeeds; organization data is denied. |

The demo issuer has already issued those public test credentials. The wallet
presents proofs; the approved mapping grants OPS membership. There is no Core
user-creation or membership-list API to call first.

For real people, a bank assigns an Azure group/app role or issues a Privado
credential through its trusted issuer. Git defines the OPS groups, permissions
and mappings. Another person joining an already mapped external group normally
requires an external membership assignment, not an OPS Git change.

## 1. Inspect the bank's configuration

Export the current public authoring files into a **new** directory:

```sh
make demo-v2-export-config CONFIG_DIR=.tmp/demo-policy
```

The command prints the current claim-to-group mappings. It exports an explicit
allowlist of public JSON documents, excluding private state, environment files,
database credentials and private keys. Existing directories are not overwritten.

| File | What it defines |
| --- | --- |
| `core/groups.json` | Admin/Deployer/Reader groups, organization-admin flag and allowed RPC methods. |
| `core/identity.json` | Trusted public identity profiles and verified-fact mappings to those groups. |
| `core/execution.json` | Native Go execution rules for contract calls and deployments. |
| `core/registry.json` | Demo contract ABI, read grants and event visibility. |
| `core/disclosure.json` | Standing rule permitting the Admin's bounded disclosure. |
| `broker/identity.json`, `broker/auth.json` | Matching identity trust and authentication/proof configuration. |

The local editor in step 6 changes only identity mappings within this bank's
three existing groups. Other exported files are inspection examples; the helper
does not apply arbitrary edits to them.

## 2. Sign in as the prepared identities

Open the Explorer URL printed by `make demo-v2-info`, then:

1. Choose **Sign in**.
2. In OPS choose `demo-deployer`, or another prepared profile.
3. Expand **Verification request** and copy its URL.
4. Open the printed demo wallet URL in a second tab, choose the matching persona,
   paste the request URL and choose **Generate and submit proof**.
5. Return to OPS, inspect the verified holder DID, choose **Use this identity**,
   then **Continue to application**.

Use separate browser profiles/private windows for simultaneous identities.
For a switch within one context, use **Sign out** and start a new login; another
tab shares its browser identity context. Short access lifetimes can require a
fresh proof after several minutes. Use the same identity/profile when refreshing.

Accept the local demo certificate warning for the printed URLs. The launcher
uses P-256 TLS certificates and does not install a system-wide CA. Process trust
is confined to the selected demo CA. For damaged/mismatched or old demo TLS
material, `./scripts/v2-demo.sh repair-tls` repairs TLS only and restarts its
consumers; identities and stored data remain.

## 3. Demonstrate wallet ownership

Open **Wallets**. The walkthrough links Admin, Deployer and Reader through the
normal challenge/sign/verify API, or verifies their retained links. It does not
seed link rows directly. The automatic scenario needs no wallet extension.

To use the actual buttons manually, import a public test account into an
isolated Ethereum browser-wallet profile. The Deployer private key is:

```text
0x0000000000000000000000000000000000000000000000000000000000000002
```

Admin uses scalar 1, Reader 3 and Outsider 4, each padded to 32 bytes. These keys
are public; use them only on this isolated chain, never for real funds.

As Deployer choose **Link wallet**, select the account, choose **Sign ownership
proof**, approve the signature in the wallet, then **Confirm link**. Choose
**Refresh links** to inspect the result. A verified link may already exist after
the automatic walkthrough. The demo identity wallet is a Privado proof tool;
it is not an injected Ethereum wallet.

Permanent unlink is outside this repeatable scenario: the UI correctly states
that the same address cannot be linked back under the current deployment rules.
Linking establishes ownership; it does not grant group membership or execution
permission.

## 4. Deploy, call and compare visibility

Run the visible walkthrough or the prepared headless check. Both use the real
Deployer identity and a genuinely signed transaction submitted through OPS.
They deploy or reuse `DemoRecord`, execute `set(subject, 171)`, and wait for a
real successful receipt, nonempty runtime and actual indexer/observer capture.
Reader's signed attempt to change the value is denied before broadcast; its
chain nonce stays unchanged. A permitted `eth_call` returns the stored value.

Run `make demo-v2-info` to recover the actual sample links later. Open the same
transaction as Deployer, Reader and Outsider. Deployer sees it; Reader sees
**This record is unavailable**; Outsider has no organization-data permission.
Open **Logs** and select the contract to compare Admin's full event subject with
Reader's masked subject. The subject is Admin's linked address and is different
from the transaction sender.

Event-entitled readers retain V1's receipt-envelope semantics: receipt `from`
and `to` may be visible. Masking a log parameter does not promise sender anonymity.
The check waits for source capture before comparing views, so an empty index is
not accepted as proof that privacy works.

The scenario also submits a second signed call with
`visibleTo: [readerActorId]`. Compare the printed **Shared with Reader** link with
the original private transaction. Reader can now see the shared transaction and
its full event subject; the original transaction stays unavailable and Outsider
is still denied. Sharing is per transaction and grants no group or write rights.
This fixture explicitly enables the contract's `allowVisibleToUnlock`; that
opt-in is why the shared event payload can be unmasked.

The application contract source is [DemoRecord.sol](../../scripts/v2-demo/DemoRecord.sol),
compiled with Solidity 0.8.35 into the checked-in artifact. Execution policies
use native Go; the OPS delivery contains no Solidity compiler or EVM policy backend.
The local node has node-owned unsigned signing disabled; the walkthrough also
checks that `eth_sendTransaction` cannot send an unsigned transaction.

## 5. Open a disclosure without customer approval

The walkthrough opens one case. To create another, sign in as Admin, choose
**Disclosures**, expand **Open a disclosure case**, and enter:

| Field | Value |
| --- | --- |
| Approved rule ID | `demo-auditor` |
| Client actor IDs | Deployer actor ID printed by `make demo-v2-info` |
| Wallet address limit | Leave empty |
| Case reference | `DEMO-001`, or another unique reference |
| Purpose | `Review the demo contract transaction` |
| Legal basis | `Isolated test scenario` |
| From / Through | Local-time interval containing the sample transaction; set Through just after it |
| Case expires in minutes | `15` |
| Data | Transactions |
| Detail level | Full |

Choose **Open case**, **Transactions**, then a row's **Details** link. Expand
**Case history** to inspect recorded activity. The customer is not asked to
approve. The same case is unavailable as Reader, while Reader's permitted
ordinary Explorer requests still work. Cases expire; create a new one if you
return later.

The legal-basis field records supplied context. This test does not establish
legal compliance, KYC or global completeness of retained history.

## 6. Change access through configuration

First try the existing read-grant example:

```sh
make demo-v2-revoke-reader
# Reader can no longer obtain the demo event; Admin still can.
make demo-v2-restore-reader
```

Each command drains OPS, prepares a new immutable bundle, updates runtime pins
and restarts. Identities, operational epochs, wallet links and transactions
remain. No customer approval or SQL policy edit is involved.

To demonstrate the claim mapping itself, use the export from step 1. Save a
rollback copy and optionally track those public sources in a local Git repo:

```sh
cp .tmp/demo-policy/core/identity.json .tmp/demo-policy-reader.json
git -C .tmp/demo-policy init
git -C .tmp/demo-policy add core broker
git -C .tmp/demo-policy commit -s -m "Record demo bank configuration"
```

Change the verified Reader-role mapping to the existing Admin group:

```sh
node --input-type=module - .tmp/demo-policy/core/identity.json <<'JS'
import fs from 'node:fs';
const file = process.argv[2];
const source = JSON.parse(fs.readFileSync(file, 'utf8'));
const admin = source.mappings.find(m => m.profileId === 'demo-admin');
const reader = source.mappings.find(m => m.profileId === 'demo-reader');
reader.groupIds = [...admin.groupIds];
fs.writeFileSync(file, JSON.stringify(source, null, 2) + '\n');
JS
git -C .tmp/demo-policy diff -- core/identity.json
make demo-v2-check-config IDENTITY_FILE=.tmp/demo-policy/core/identity.json
make demo-v2-apply-config IDENTITY_FILE=.tmp/demo-policy/core/identity.json
make demo-v2-check-mapping EXPECT=admin
```

Check prepares and loads both complete candidate bundles before draining
anything. Apply rechecks, drains OPS/Explorer, selects the source and regenerates
both matching identity catalogs and dependent runtime pins before restart.
Keys, provider trust and proof requirements stay fixed. Invalid input rejects
before drain. On a later failure, the launcher attempts to stop affected
consumers and retains the selected source for a corrected retry or resume.
Operational data is not reset.

Sign out and sign in again as `demo-reader`, using the same role credential.
The new permissions come from the file mapping. The change affects **every
holder satisfying that verified profile/predicate**, not one named user.
The check verifies the organization-admin flag, transaction access and an allowed
signed contract call. The event's subject address remains masked for this wallet;
organization-admin access does not make every private address public.
Current requests use the newly selected mapping; a fresh login avoids renewal
of a family bound to the previous identity catalog.

Restore ordinary Reader access:

```sh
make demo-v2-apply-config IDENTITY_FILE=.tmp/demo-policy-reader.json
make demo-v2-check-mapping EXPECT=reader
```

The selected mapping survives resume. The previous source is also retained
offline as `/demo/identity-previous.json`, but use the original host copy or Git
revision for deliberate rollback: the internal previous file changes on each
apply. Restore Reader before repeating the standard walkthrough, which checks
the original separation between Admin, Deployer and Reader.

Git supplies review and approval. OPS does not watch GitHub or automatically
apply a commit. Calling the local apply command is the demo operator's explicit
deployment action; a real pipeline must select reviewed files and trusted
manifest digests. This editor is a demo helper, not a Core mutation API or
generic custom-organization provisioner. Adding another organization requires
its node/deployment/observer bindings as well; see the operational guide.

## 7. Stop and resume with retained state

```sh
make demo-v2-down
make demo-v2-resume
make demo-v2-info
make demo-v2-check-mapping EXPECT=reader
```

The same identity, verified wallet links, selected configuration, contract and
transaction history remain. `make demo-v2-down` stops owned services without
removing their volumes. `make demo-v2-reset` explicitly deletes this demo's
state and should only be used when a fresh baseline is intended. Cleanup
rejects collisions with another checkout's resources.

## Initial installation and deployment details

For a machine without cached prerequisites, use `make demo-v2`. It builds the
images and downloads pinned dependencies/circuits. Allow more free space for
that initial build than for running an existing demo. Use Node 24 and Docker
with Compose/Buildx. Host networking works on Linux/OrbStack; enable it on
Docker Desktop. Listeners bind loopback on persisted random ports. Registry
access uses a separate credential-free Docker configuration, without Keychain.

Explorer/indexer revisions are locked in
[dependencies.json](../../scripts/v2-demo/dependencies.json). Explicit local
source overrides must be the exact clean revisions. There is no branch fallback
or silent test skip. Logs and public URLs are under `.tmp/v2-demo/<project>/`;
`OPS_V2_DEMO_PROJECT` selects a different isolated project.

Localhost cookies span ports, so these trusted local services do not demonstrate
cross-host cookie isolation. The separate origin/session controls are described
in the testing guide. The issuer's `polygon:mumbai` identifier names its
controlled fixture namespace, not a live Mumbai deployment. Hosted Azure,
live role issuance and a particular wallet vendor are separate qualifications.

Serving containers receive only their own selected files, leaf TLS keys and
restricted operational credentials. Offline bootstrap retains the owner
credentials and CA private key separately. This walkthrough uses the OPS
preflight submission mode; qualification of Guard v1's signed-approval mode is
covered separately, not demonstrated by this stock Reth node.

See [operational deployment](v2-operational-server.md),
[policy authoring](policy-authoring.md) and [required automated checks](v2-testing.md).
