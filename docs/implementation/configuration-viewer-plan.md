# Read-only configuration viewer: implementation plan

This is a plan, not a description of a completed viewer. It implements the
[recorded product decision](../architecture/configuration-viewer-decision.md).
The existing application still imports and edits local proposals.

## What the user will see

1. Open RBAC → Configurations. Available server folders appear as tabs.
2. Open a configuration. The familiar organization/group/contract/rule views
   display that file set and its relationships; source files can also be read.
3. Open another configuration and the display changes to that configuration.
4. External changes refresh the display. A deleted selected folder clears the
   view and asks the user to choose another.

There is no Edit, Save draft, Compare, Validate, Approve, Publish or Review &
export workflow in this viewer. It does not display revision history or claim
that a candidate is active. All configuration changes and approvals happen
externally. Operational actions remain separate and retain their authorization.

## 1. Define the read-only input and access contract

Add an optional `configurationViewer` setting to the pinned operational server
configuration. It specifies an absolute public-source directory, explicit
`single`/`folders` layout and a default audience. Absence of the setting leaves
the viewer unavailable with a clear message; it never falls back to browser
imports or Core's artifact directory.

An audience has `ownerOrganizationIds` and optional `operatorActorIds`. Access
requires a current verified human with an existing full/read-only admin role,
and either an explicitly listed actor ID or admin/read-only roles in **every**
owner organization, with at least one owner configured. Precisely:

```text
verifiedHuman && currentAdminInAnyOrganization &&
  (actorExplicitlyListed ||
    (ownerOrganizationIds.length > 0 && everyOwnerHasCurrentAdminRole))
```

Here an admin role includes full and read-only admin. Empty owners do not grant
access to an actor absent from the explicit list. An optional named folder
override replaces the default audience; otherwise children inherit it. Audience
settings come from trusted deployment configuration, not preview files.

The owner organizations control access to the project; they are not inferred
from organizations declared in that project. This permits an authorized owner
to inspect a proposal introducing a new organization. Permission covers the
whole project; there is no misleading promise to redact a global broker or
identity file for a single tenant. Shared roots require deliberate deployment
audiences. Newly appearing children inherit only their preauthorized namespace.

Use `draft.json` plus its referenced public JSON files initially. Support a
flat root or named roots within each candidate, preserving `core`/`broker`
inspection. Strip the candidate directory prefix before reusing the current
bounded document decoder. Do not create an artifact-to-draft converter or
compile/approve the viewed files.

## 2. Add a bounded read-only backend outside Core

Create an operational configuration-viewer package, wired by `v2server`, with:

- `GET /api/v2/configuration/sources`: authorized IDs and folder labels only.
- `GET /api/v2/configuration/sources/{id}`: the complete selected public project.

The project response can reuse the existing bounded roots/files/base64 envelope
and decoder. An ID selects a discovered configured folder; it is not a path.
Do not add an arbitrary-file endpoint, upload endpoint or mutation methods.
Unauthorized folders are absent from the list; unknown and unauthorized IDs
are indistinguishable on point reads.

Reuse verified-session and organization-role handling already used by native
self/diagnostics operations. Recheck permission and original credential expiry
after file work and before returning a body or an unchanged response. Browser
requests keep the existing controller's cancellation and identity fences.

Read through a confined filesystem root. Reject traversal, symlinks and
nonregular selected files; ignore adjacent files, dotfolders and Git metadata.
Read only the index, its known flat references and explicit broker public pins.
Do not resolve `fromEnv`, open credentials or make preview-directed network calls.

Preserve the current input ceilings: 16 named roots, 2,048 input files,
1 MiB per file and 64 MiB total source bytes. Bound directory enumeration as
well as the returned reference closure; do not scan unlimited adjacent files.
Bound candidate count explicitly (initial ceiling: 128 candidates). Include base64
and JSON overhead in a source-specific wire cap of 90 MiB. Keep other native
operation responses at their existing 2 MiB limit. A large-source transport
must retain finite deadlines, byte counting and final owner/expiry checks.

Never preload all candidates. Allow at most two captures globally, with a
384 MiB source-buffer budget across in-flight work and cached representations.
Charge raw and encoded copies separately and reserve the worst-case capture
bytes before admitting work; evict cache entries or reject busy work rather
than exceed that budget. Waiting is finite and bounded by original credential
expiry. These are source-buffer limits, not a claim about total process heap.

Capture referenced files into detached memory and publish the captured project
as a unit. Recheck the configured parent and candidate directory identities,
file identities, indexes, reference closure and bytes after capture; retry a
detected race once, then return unavailable. A held descriptor to a withdrawn
folder must not publish old contents as the current candidate.

For coherent publication, the external producer stages a complete folder on
the same filesystem and renames it into an absent candidate path. Same-name
replacement withdraws the old folder first and may briefly be unavailable.
Keep exposed files unchanged when coherent observation is required. This does
not require portable rename-over-nonempty-directory support or a new pointer
protocol. In-place editing remains best effort; double reads of mutable files
do not establish an atomic published revision.

Invalid trusted server settings fail closed through the existing configuration
loader. A missing, removed, unreadable or malformed external candidate is a
viewer error only, not an RPC/Core readiness dependency.

## 3. Refresh automatically without a revision store

Use polling first; no new websocket, filesystem-notification dependency or
shared store is required. Poll the list and selected source every two seconds
while the view is visible, and refresh immediately on focus or explicit Refresh.
There is at most one in-flight poll per resource. Stop on unmount, loss of access
or unresolved/expired authentication.

Use conditional source responses so an unchanged 64 MiB project is not repeatedly
downloaded. Keep only bounded current observations in process memory: a current
source tag, raw/project response, and the referenced-file metadata needed for
change detection. Use a small current-observation map with bounded eviction,
not a new cache framework or revision history. Check the referenced-file
metadata on observation; recapture on changes and on explicit Refresh, with a
full-read backstop attempted at least every ten seconds for visible sources.
That interval is a scheduling target, not an availability SLA. The cache evicts
by bytes (192 MiB maximum across all retained raw/encoded representations,
also charged to the global budget) and coalesces captures of the same source.
A miss is a bounded fresh read, not a stale fallback.

An internal content tag is for conditional requests and stale-response fencing;
it is not shown as a policy revision or approval. An unchanged response still
requires current authorization, path availability and final expiry checks.
Add narrowly scoped conditional-response support for these GETs; do not weaken
the generic native transport's method, header, byte or origin restrictions.

On any selected-source read failure, including deletion, access loss, malformed
content or unavailability, clear the selected data and open inspections. Do not
require prior confirmation that files changed. A late request cannot resurrect
removed data or replace a newer selection. On a valid update, rederive details
using real stable record IDs; close removed details instead of retaining copied
objects or array indexes. For catalog rows without a stable ID, close inspection
on update rather than inventing persistent IDs or changing the source schema.
Switching folders also clears old record selections and raw-file views.

This is current-view bookkeeping, not durable state, proposal ownership,
multi-instance coordination or Core policy activation.

## 4. Replace local authoring with read-only views

Keep the existing RBAC, Identity and source-setting presentation and relationship
inspection. Add the Configurations page/folder tabs; retain the selected source
in the verified document context across ordinary page navigation. A single
configuration may open initially; multiple configurations require a choice.
Deletion must not silently choose a different source.

Split the current source document loader/read helpers from its mutations. Reuse
the bounded raw-byte and display parsing behavior. Unsafe numeric values or
unsupported shapes remain inspectable as source with a simple display message;
they must not be silently rounded or displayed as a different permission.

Remove the V2-only authoring paths:

- Edit-mode toggles, add/edit/remove actions and form submission callbacks.
- Local file/folder and saved-draft pickers; raw text editing and draft repair.
- Proposal serialization/export, dirty-form warnings and draft recovery state.
- Original/proposed comparison, imported Go reports and CLI handoff panels.
- Browser scenario authoring/simulation-report import and ABI upload helpers.
- Review & export header action and running-selection comparison.

Retain read-only ABI/method/event displays, dependency/relationship views,
search, paging, selection colors, keyboard behavior, raw source inspection and
clipboard actions for already displayed public values. Preserve shared V1
components still used by V1. Remove obsolete wrappers rather than reverting
the preceding UI adaptation.

Replace `SourceDraftMemory` and authoring scopes with a smaller read-view store:
selected folder/root, current project and harmless inspection/search state.
Carry forward identity/expiry/context ownership and stale-result rejection;
remove editing, export-before-leave and dirty-proposal behavior. Preview
organization/admin fields never change actual authorization or operational scope.

Route old configuration bookmarks to the new read-only configuration view;
they must not resurrect an editor. Remove `ServingSelection` and the UI-only
`/api/v2/self/selection` endpoint, DTO, transport allowance and associated
workflow tests after checking the full usage inventory. Keep ordinary `/self`,
operational diagnostics/build information and external CLI inspection.

Keep the Go compiler/validator, external CLI/agent authoring tools and immutable
runtime loader. Remove a helper only when it is exclusive to the deleted browser
workflow and has no external publication, demo-fixture or V1 consumer.

### File-level cleanup

Frontend paths below are relative to `frontend/src/v2/web/`. Split mixed files
before deleting their writer helpers; retaining a view means preserving its
readable presentation, not disabling every field in an editing form.

| Current files | Planned treatment |
| --- | --- |
| `AdminApp.tsx`, `SourceWorkspacePage.tsx`, `navigation.ts` | Connect server folder selection and read-only views; remove draft guards and Review & export navigation. |
| `sourceProject.ts`, `workspace.ts` | Extract bounded byte decoding, immutable types and display projections; delete source mutation and browser-picker helpers. |
| `sourceDraftMemory.ts`, `SourceAuthoringScope.tsx`, `sourceAuthoring.ts` | Replace with read-only selection/view state after transferring account, role, expiry and stale-response guards. |
| `SourceReview.tsx`, `SourceScenario.tsx`, `SourceScenarioBuilder.tsx`, `ServingSelection.tsx`, unused `WorkspacePage.tsx` | Delete obsolete browser workflows and their exclusive imports. |
| `ExecutionRuleForm.tsx`, `executionRules.ts`, `registryABIText.ts` | Delete editor-only code after detaching read-only consumers. |
| `SourceOrganizations.tsx`, `SourcePermissions.tsx`, `SourceContracts.tsx` | Keep tables, group cards, permission colors, filters and relationship dialogs; remove source writers. |
| `SourceContractABI.tsx`, `SourceReadGrants.tsx`, `SourceExecution.tsx`, `ExecutionRuleDetails.tsx`, `executionABI.ts` | Keep structured ABI, grants and execution details; remove upload/edit/scenario/report paths. |
| `SourceCatalogs.tsx`, `SourceClaimMappings.tsx`, `SourceComplianceSettings.tsx`, `SourceRecords.tsx` | Keep source inspection; remove catalog writers. Replace copied-object/array-index selections with current stable IDs. |
| `adminAccess.ts`, `operationsTransport.ts`, `controller.ts` | Keep actual verified-role/session authorization; remove edit-only permission helpers and add narrowly bounded source GET handling. |
| Shared `frontend/src/components/` presentation and V1 forms | Keep reusable views, layout and styling; V1 still consumes its form components. |
| Login/account/wallet and `Native*` operational pages | Keep their behavior and real authorization; the viewed candidate supplies none of their privileges. |
| `scripts/v2-demo/`, relevant frontend tests and current guides | Replace only import/edit/export assumptions; retain parsing, privacy, presentation, CLI and operational coverage. |

The existing CLI `policy unpack` remains a separate compatibility contract even
after browser package export disappears. Do not delete it just because this
viewer no longer exports proposals.

## 5. Adapt demo, checks and documentation

Provision a separate read-only **source** directory for the demo and give its
existing admin/read-only identities an explicit viewer audience. Preserve the
demo's actual approved runtime artifacts, keys, identity state, wallets, chain
data and audit history. Candidate fixtures and source-folder changes do not
invoke the demo's runtime apply/revoke commands.

Replace browser authoring checks with actual folder-backed inspection checks.
Retire tests asserting removed features; retain and adapt privacy, auth, parsing,
display, ABI, numeric-fidelity, relationship and clipboard regressions. Mixed
test files must be reviewed assertion by assertion, not removed by filename.

Required evidence:

- Single flat project, single named-root project, and multiple candidate folders.
- Authorized discovery, unauthorized/unknown IDs, all-owner/explicit-operator
  audiences, empty owners with a nonlisted actor denied, and new preview
  organizations without new live privileges.
- Path/symlink/credential exclusion, exact file budgets, base64 wire limits,
  cancellation, expiry and authorization changes during reads and unchanged replies.
- Concurrent requests across distinct large sources respect global capture,
  buffer and wait limits; neither cache misses nor eviction preload candidates.
- Add/update/delete/folder replacement while viewing; no stale nested dialog,
  cross-source response or accidental auto-selection after removal.
- Actual UI relationship examples: group → contract/read grant and execution
  binding → contract/function, with the retained V1 style and responsive layout.
- No configuration mutation/approval routes or editing controls in the native
  delivery; no new Core, SQL, Git or secret-resolving viewer dependency.
- Existing QR login/header, operational actions, CLI/agent checks and V1 build
  remain valid. Full Explorer/indexer checks are repeated only if those trees change.

Update the workspace, operational-server and local-demo guides in the same
implementation changes that deliver the corresponding behavior. Rename the
workspace guide to reflect viewing and fix its links. Historical evidence stays
historical; do not relabel old local-import screenshots as folder-backed proof.

## Delivery sequence and review gates

1. Record this scope and review the source inventory and access/folder contract.
2. Implement the read-only backend/transport and read-view state. These can be
   developed in parallel against the agreed response contract.
3. Connect the retained views, remove obsolete authoring and retire its API/UI
   seams. Review the combined dependency/deletion inventory independently.
4. Update demo, retained tests and current guides. Run focused integration and
   real desktop/mobile browser checks, then independent final review.

Do not leave a hidden editor or a parallel old workflow in the delivered tree.
Keep recoverable implementation history in Git instead. Do not implement a
proposal database, Git connector, diff service or longer authentication lifetime
as part of this cleanup.
