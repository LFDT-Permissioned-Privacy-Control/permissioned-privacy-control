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
Before restarting OPS, resume stops the serving processes and explicitly runs
the offline owner activity-schema upgrade, including for an existing demo.
The upgrade preserves recorded history, source identity and generation; it
does not initialize a new activity source or reset the local buffer.

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

The original Explorer layout and named data pages use native session/data
adapters, including approved-ABI contract Read and wallet-backed Write controls.
Admin reuses the original layout, organization forms, group cards and account
presentation. Its source workspace edits and exports complete file proposals;
compliance, disclosure, organization access logs and diagnostics use their native APIs.
The walkthrough proves its listed API/privacy operations. File authoring and
ordinary wallet setup have separate manual steps and qualification below.

After the complete walkthrough has created a sample transaction, run
`make demo-v2-ui-preview` for a headless check of these adapted screens. It
exports a fresh source copy, performs real Privado login/renewal, imports the
source into Admin, and saves screenshots and `ui-preview-results.json` under
`.tmp/v2-demo/<project>/`. It preserves the current demo data and configuration.
The exported folder is also suitable for the manual Admin steps below.
The preview includes fresh and repeated signed-out visits, mobile entry,
identity-proof and confirmation screens, and the original Account cards with
verified wallet links. Its expiry checks advance only the browser clock past
the original signed expiry to verify that private displays clear; they do not
claim to test a provider or server clock.

`make demo-v2-ui-parity` checks the running demo's native transaction pages with
the four real proof personas. It checks console entry and protected API denial
for non-admins while retaining their own Account and Explorer access. It pairs API reasons with **Mine**, **My Org**,
**Counterparty** and **Shared** badges, checks denied views and compact transfer
details, and creates, reads and revokes one disclosure case while requiring
ordinary RPC and Explorer results to remain unchanged. It uses the private and
shared sample transactions from a passing walkthrough; run the walkthrough
first if they are absent. Results and screenshots are stored in
`ui-parity-results.json`, `admin-entry/` and `ui-parity/` under the demo directory. The full
functional walkthrough also runs these checks. The unmapped outsider is not a
second-organization fixture; server canonicality tests cover reorg fences,
while this UI check does not change the chain's canonical history.

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

Export the current configuration sources into a **new** directory:

```sh
make demo-v2-export-config CONFIG_DIR=.tmp/demo-policy
```

The command prints the current claim-to-group mappings. It exports an explicit
allowlist of JSON documents, excluding private state, environment files,
database credentials and private keys. Policy sources can still be confidential;
the export does not publish them. Existing directories are not overwritten.

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

To inspect them in the familiar Admin UI, open the OPS origin printed by
`make demo-v2-info`, followed by `/admin`. Complete sign-in or the fresh Privado
proof requested on reload using **Demo Admin** (or a configured organization
admin/read-only admin). If shown, choose **Open configuration workspace**.
Choose **Import source folder** and select the exported parent containing both
`core` and `broker` (a single `core` root also works for inspection).
The **Organizations** tab shows Demo Bank. Select its row to open that bank's
groups, or choose Demo Bank in **Scope** before opening the **Groups** tab.
You can then inspect Admin, Deployer and Reader. A group's gear button
shows its declared permissions. This source is a local draft, not a report of
the revision currently served by every OPS instance. Importing it applies no
permissions and sends no source files to OPS. Account menu → **Account** opens
the original identity, session, organization and linked-address cards, backed
by the native V2 identity and wallet APIs.

As Demo Admin, choose **Check this OPS instance** in the source workspace to
read its selected Core revision and artifact digest. Different draft labels
are reported explicitly; matching labels still do not compare file contents.
This checks one OPS instance, not the broker or the whole deployment.

Choose **Edit local proposal** to create organizations/groups or edit their
permissions, contracts, read grants and execution rules under **RBAC**.
**Identity** contains **Profiles** (Azure and Privado) and **Claim mappings**.
Use **Disclosure → Rules draft**, **Compliance → Policy draft** and **Settings**
for their configuration documents. Imported files and unfinished form fields
stay in the same local draft as you move between these sections. **Review & export** compares and exports the complete
proposal; **Open saved draft** restores those files later without changing the
running configuration. Run the actual Go
`policy unpack`, `prepare`, `check` and optional `simulate` commands from the
[policy workspace guide](v2-policy-workspace.md). New organizations also require
explicit compliance entries, matching Core/broker identity references, node
bindings and deployment preparation described there. The browser does not
activate proposals or provision a new organization's infrastructure.

## 2. Sign in as the prepared identities

Every signed-in identity can open its own Account and wallet settings. The
admin console requires an organization-admin or read-only-admin role. Demo
Reader, Deployer and Outsider have no admin navigation and cannot open console
pages directly. Deployer's contract execution permissions do not grant
organization administration.

Once per browser profile, open the printed OPS and demo wallet URLs and accept
their local certificate warnings. Chrome may remember the exceptions separately
for each port. The launcher does not modify Keychain or install a system CA.

Open the Explorer URL printed by `make demo-v2-info`, then:

1. Choose **Sign in**.
2. In OPS choose **Demo Deployer**, **Demo Admin**, **Demo Reader** or
   **Demo Outsider** under **Development Only**. Allow the local wallet popup
   when the browser asks. If the wallet window shows its local certificate
   warning, accept it; OPS allows up to two minutes for this setup, bounded by
   the original application login's expiry.
3. Wait while the wallet generates a fresh proof. OPS verifies the exact selected
   holder, finishes that login and continues to the original application.

If an existing Privado session needs a fresh proof, choose the same demo identity
under **Development Only**. It completes that existing verification request and
keeps the same session. **Cancel demo verification** closes only the helper;
**Cancel sign in** abandons the verification request. Ordinary wallets use the
QR code or wallet link under **Use a wallet manually**.

For a direct visit to OPS, the same buttons open the configuration workspace for
an administrator and Account for other identities. **Cancel demo sign in**
retires the current attempt; choosing another identity starts a new one. Nothing
is retried automatically after an uncertain confirmation.

These buttons are compiled only into the local demo image. A normal V2 build
keeps the ordinary Privado and Azure login. To inspect the ordinary Privado
flow in the demo, expand **Use a wallet manually**, choose
**Continue with Privado ID**, expand **Verification
request details**, and copy its URL to the printed demo wallet page. Select the
matching persona there and choose **Generate and submit proof**; then inspect
the verified holder in OPS and confirm it.

All four personas use one `demo-privado` connection and the same verification
request. The wallet proves whichever approved roles that holder can prove; OPS
maps only those verified facts to groups. The outsider proves its identity with
no role facts and receives no groups. An omitted role means “not proved”; it is
not evidence that the holder cannot have that role.

`make demo-v2-check-login` checks the actual buttons, holder matching,
cancellation, blocked popups and untrusted certificates in temporary browser
profiles. It uses real proofs and saves results under
`.tmp/v2-demo/<project>/demo-login/`.

Use separate browser profiles/private windows for simultaneous identities.
For a switch within one context, use **Sign out** and start a new login; another
tab shares its browser identity context. Short access lifetimes can require a
fresh proof after several minutes. A reload can reuse a still-valid server
session, preserving the original evidence age and expiry. It never extends old
permissions. Use the same identity/profile when a fresh proof is required.

Accept the local demo certificate warning for the printed URLs. The launcher
uses P-256 TLS certificates and does not install a system-wide CA. Process trust
is confined to the selected demo CA. For damaged/mismatched or old demo TLS
material, `./scripts/v2-demo.sh repair-tls` repairs TLS only and restarts its
consumers; identities and stored data remain.

## 3. Demonstrate wallet ownership

Open Account → **Linked Addresses**. The walkthrough links Admin, Deployer and Reader through the
normal challenge/sign/verify API, or verifies their retained links. It does not
seed link rows directly. The automatic scenario needs no wallet extension.

To use the actual buttons manually, import a public test account into an
isolated Ethereum browser-wallet profile. The Deployer private key is:

```text
0x0000000000000000000000000000000000000000000000000000000000000002
```

Admin uses scalar 1, Reader 3 and Outsider 4, each padded to 32 bytes. These keys
are public; use them only on this isolated chain, never for real funds.

As Deployer choose **Link Wallet**, select the account, choose **Sign ownership
proof**, approve the signature in the wallet, then **Confirm link**. The linked
address appears in the list. A verified link may already exist after
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

### Use the Explorer contract forms with your Ethereum wallet

Open the contract's **Contract** tab as Deployer. The approved ABI supplies
**Read contract** and **Write contract**. Open `value()` and choose **Query**
to read through your current Explorer session and OPS permissions.

For a manual write, run the separate `jwt-injector` helper in its native V2
mode on the wallet's machine. Sign in to OPS Account as the same Deployer,
choose **Download wallet token**, and keep that file private with mode `0600`.
Use the current OPS/Explorer URLs printed by `make demo-v2-info` and copy the
approved chain ID/genesis hash from Explorer's **Network setup** page:

```sh
python -m jwt_injector --native-v2 \
  --jwt-file /absolute/private/path/ops-wallet-token.jwt \
  --port 8546 --upstream https://localhost:OPS_PORT \
  --org-id 11111111-1111-4111-8111-111111111111 \
  --chain-id 31337 --genesis-hash COPIED_GENESIS_HASH \
  --ca-file /absolute/path/to/demo-control-directory/ca.crt \
  --cors-allow-origin https://localhost:EXPLORER_PORT
```

Run the command from an installed native-mode `jwt-injector` checkout. The demo
control directory is `.tmp/v2-demo/<project>` in this OPS checkout. Replace the
explicit placeholders; the helper verifies TLS, network and the original token.
If a wallet sends its extension Origin, add that exact trusted Origin to the
comma-separated allowlist. Do not use a wildcard.

Open `set(address,uint256)`, enter the helper origin
`http://127.0.0.1:8546`, choose **Connect wallet**, and allow the browser's local
network access prompt if shown. Select the linked Deployer account. Enter the
Admin address as `subject` and `171` as `next`, choose **Write**, then review the
transaction in the signing wallet. **Check receipt** reports the actual result.
An already-known network may retain its old RPC URL: use **Manual wallet network
setup** to copy the current private temporary URL into that wallet's network
settings, then reconnect. Keep that URL private.

This compatibility flow needs a fresh token file and reconnection when the
original five-minute session expires. It does not silently renew wallet
credentials. Once handed to the wallet, reject there to cancel; closing the
page cannot undo a sent transaction. After an uncertain outcome, check wallet
activity before another send. Automated qualification uses an injected signing
provider and the real helper/OPS/node; a particular extension's interface is a
separate environment check.

## 5. Open a disclosure without customer approval

The walkthrough opens one case. To create another in **Explorer**, sign in as Admin, choose
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
| Data | Transactions and Events |
| Detail level | Full |

Choose **Open case**, **Transactions**, then a row's **Details** link. Return to
the case and choose **Events** for the contract log cards. Topics and data are
shown directly; **Transaction details** expands the hashes. **Continue** can advance through a page containing
no eligible logs. **Download this page** saves only that page. These are events
from transactions covered by the case, not all activity mentioning a customer.
Full includes the whole event payload, possibly other parties in a batch;
Pseudonymous and Redacted withhold all raw topics, data and hashes. Expand
**Case history** to inspect recorded activity. The customer is not asked to
approve. The same case is unavailable as Reader, while Reader's permitted
ordinary Explorer requests still work. Cases expire; create a new one if you
return later.

The legal-basis field records supplied context. This test does not establish
legal compliance, KYC or global completeness of retained history.

For **OPS Admin → Disclosure**, the equivalent control is **Create case**.
Use standing rule `demo-auditor`, keep your own recipient actor, enter Deployer's
actor ID as the target, and supply a unique reference, purpose and test legal
basis. Times here use **UTC**. The default expiry is 15 minutes; the demo rule
allows at most 20 minutes. Select **Compliance report** under Resources for the
finance view. After creating the case, select that data resource and choose
**Admission decisions → Read permitted data**. You can narrow the target/time,
page through evidence and **Download this page**. **Summary report** counts all
matching retained decisions at its observation time; it does not inline every
decision or cap the total at 100. The page download is not a full export.
Select **Events** under Resources to author a case with separate Events
authority. The prepared demo standing rule includes it; older prepared demo
configurations need regeneration with the current demo tools before that rule
can authorise Events.

In **OPS Admin → Access Logs**, Demo Admin can inspect its organization's sealed
request records directly; no disclosure case is required. Start with the last
24 hours, then search an exact method, actor or request reference. From/To use
UTC with **To excluded**. Results show the selected sealed snapshot and retention
floor; they are not a complete live traffic feed. Reading the logs is itself
durably recorded. Detailed denial reasons absent from old records remain absent.

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
rollback copy and optionally track those configuration sources in a local Git repo:

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
const admin = source.mappings.find(m => m.id === 'demo-admin');
const reader = source.mappings.find(m => m.id === 'demo-reader');
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

Changing trusted identity profiles can also change Explorer's approved SSO
source. Its existing session store deliberately rejects a different source
digest. Drain Explorer before using the offline `sso-v2-admin` tool with the
new source, its exact SHA-256, `--action drained-recover --traffic-drained`.
This invalidates Explorer login contexts; people sign in again. It does not
reset wallets, chain data, disclosure cases or access logs. A normal `resume`
never performs that recovery automatically. Plain permission-mapping edits
that leave the trusted profiles unchanged do not need this SSO transition.

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
required separately and is not demonstrated by this stock Reth node.

See [operational deployment](v2-operational-server.md),
[policy authoring](policy-authoring.md) and [required automated checks](v2-testing.md).
