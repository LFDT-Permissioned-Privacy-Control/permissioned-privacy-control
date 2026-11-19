# Native policy source workspace

The Admin workspace imports a `draft.json` source folder, or a parent containing
separate named Core and broker folders. It reads the documents referenced by the
drafts and broker public-context pins. Adjacent secret files are not imported.
Files remain in the selected page's memory and are removed on account replacement,
sign-out or expiry. Export before leaving the session; a saved package can be
opened again with **Open saved package**.

**Edit local proposal** enables organization/group, contract/read-grant,
execution, identity-profile/fact-mapping, standing-disclosure and platform source
editing. These controls edit files only. They do not create Core users, contact
providers, resolve environment credentials, update a running policy, or grant a
live role. The current account's organization roles are shown separately.
Complex execution and source fields retain their native JSON representation.
The Configuration tab includes original/proposed source comparison and complete
source export, including unchanged referenced files.

Raw source text immediately joins the local proposal and its export, including
unfinished JSON. Switching files does not discard it. Execution candidate source
opens the same tracked editor. Repair draft syntax before Go preparation or semantic editing. Saved packages retain explicitly exported orphaned files for repair;
folder imports still read referenced files only. Browser forms are disabled when
a document contains an unsafe integer/nonfinite number or an unsupported document
or nested policy version. Raw text and exact-byte export remain available; this
fidelity guard does not replace Go validation.

## Validate and hand off

Use the `ops-v2` executable from the same release as the target deployment.
Export `ops-source-package.json`, then unpack to a new directory:

```sh
ops-v2 policy unpack --file ./ops-source-package.json --output ./source-NEW
```

Each exported root becomes its own subdirectory. For each changed root, prepare
a new artifact using its explicit supported profile:

```sh
ops-v2 policy profiles
ops-v2 policy prepare --source ./source-NEW/core --output ./artifact-NEW --profile catalog-runtime-creation-observed/v1 --consumer delivery
ops-v2 policy check --bundle ./artifact-NEW --expected-digest sha256:REVIEWED_DIGEST --environment local --chain-id 31337 --profile catalog-runtime-creation-observed/v1 --consumer delivery
```

Use the matching profile/consumer/environment/chain for the intended deployment;
these examples are not a universal profile selection. `prepare` uses the same Go
compiler and pinned loader as `check`. `unpack` only reconstructs source bytes.
All output directories must be new; neither command overwrites an existing one.
Reports describe local validation and do not establish approval or readiness.
An imported report in the UI is explicitly operator-supplied information, not a
certificate that the serving deployment or every current source byte matches it.

Review the source changes and exact artifact digest through the organization's
approved Git process. Coordinate the complete Core/broker/SSO/runtime/read-policy
pins, organization node configuration and environment references. Materialize
approved bundles read-only and deliberately drain/restart the selected deployment.
Check readiness and current identities afterward. Rollback selects a previous
approved compatible image and complete bundle set; exporting a source package
never changes an active pointer.

For a new organization, the organization/group forms begin the proposal. Go
validation also requires its explicit entry in `compliance.organizations`,
contract registry and execution policy. Give the Core and broker roots the same
identity catalog and matching organization/group references. Keep each root's
supported profile: the broker's empty registry/execution scaffolding is not a
copy of Core's history-enabled runtime documents.

The runtime's `data.nodes` must contain exactly the Core organization IDs.
`protected.nodes` instead contains exactly the data organizations referenced by
standing disclosure rules; adding an organization does not by itself add a
disclosure rule. Coordinate the selected policy, node credentials, protected
source plan and expected operational-store state with offline deployment tools.
The source editor does not create node credentials, initialize operational
stores or deploy an arbitrary new organization. Successful local Go validation
does not establish that these deployment prerequisites are in place.

## Offline execution scenarios

The Execution Policy tab exports `ops-policy-scenario.json`. Run the actual Go
reference evaluator against an explicitly pinned artifact:

```sh
ops-v2 policy simulate --bundle ./artifact-NEW --expected-digest sha256:REVIEWED_DIGEST --environment local --chain-id 31337 --profile catalog-runtime-creation-observed/v1 --consumer delivery --scenario ./ops-policy-scenario.json
```

The bounded format is `ops.policy-scenario/v1`, with `context` and `frames`.
Context names follow the native Go context: required `Org` and `Groups`, optional
`Signer`, `LinkedAddresses`, `Claims` and `GroupSourceClaims`. Each frame names
`callType` (`call`, `staticcall`, `delegatecall`, `callcode`, `create`, `create2`),
`storageAddress`, `codeAddress`, `calldata` as `0x` hex, `value` as an exact decimal
string, `depth`, and `facts`. Optional facts use the corresponding native Go Frame
names, including `CodeOrg`, `StorageOrg`, `GroupClaims`, `CallerAddress` and native
creation facts. Facts cannot repeat the separately named frame fields. No
`ReadRecord` callback or remote dependency is accepted.

Scenarios are limited to 1 MiB, 256 frames, 256 KiB aggregate calldata, 256 context
or frame group claims, and 1,024 linked addresses. The result binds the exact
scenario byte digest and selected manifest digest. `hypothetical` is true;
`approved` and `deploymentVerified` are false. The decision calls the same native
Go evaluator, but depends on operator-supplied assumptions. It does not verify a
person's current claims, establish node/owner facts, run an EVM call, or prove
compiled Guard equivalence. Production admission continues to acquire its own
verified facts and observed execution.
