# Decision: read-only configuration viewer

Decision recorded: 23 November 2026. The operational Admin viewer implements
this decision. See the [configuration viewer guide](../implementation/v2-configuration-viewer.md)
for deployment and use.

## Product purpose

Admin displays configuration supplied by an external system. Opening a
configuration changes the organizations, groups, contracts, permissions and
relationships shown in the configuration dashboard. It does not change the
running service's configuration or the caller's permissions.

An external system creates, edits, approves, publishes and removes the files.
That system may materialize different candidate configurations in separate
folders. Admin does not clone branches or integrate with Git.

The earlier product handoff described policy-file editing in Admin. This
decision replaces that authoring workflow for the configuration viewer.

## Required behavior

- Discover configurations in an operator-configured server directory. Support
  either one configuration or immediate child folders containing configurations.
- Present those folders as configuration tabs in RBAC. Reuse the established
  readable organization, group, contract, grant and execution-rule views.
- Keep the chosen configuration across normal navigation between configuration
  pages. Provide read-only inspection of the actual referenced JSON files.
- Refresh automatically when external folders or files change. Removing the
  selected configuration clears its displayed data and closes its inspections;
  another configuration is not selected silently.
- An incomplete or unreadable configuration gets a simple load error. Display
  updates replace the complete captured project, including open details, rather
  than merging fresh rows into old configuration data.
- The viewer has no configuration editing, draft saving, proposal database,
  approval, publication, diff viewer, revision history, validation-report badges
  or running-version comparison. Revision fields present in a source file remain
  ordinary source content; the viewer does not manage them.

## Folder contract

The first implementation reads the existing `draft.json` authoring sources and
their explicitly referenced public JSON documents. One logical configuration
can contain one flat source root or existing named roots such as `core` and
`broker`. Selecting a candidate must not confuse these roots with other
candidate configurations.

The deployment explicitly chooses `single` or `folders` layout:

```text
single: /review/draft.json
    or: /review/core/draft.json + /review/broker/draft.json

folders: /review/candidate-a/core/draft.json
         /review/candidate-a/broker/draft.json
         /review/candidate-b/draft.json
```

The viewer does not infer an arbitrary Git repository's layout or recursively
search it. Compiled `manifest.json` artifacts used by Core are a different
format; they are not an automatic fallback for the source viewer.

For coherent publication, the external producer prepares a complete candidate
outside the visible candidate namespace on the same filesystem, then renames it
to an absent candidate path. An ignored dot-prefixed staging directory on the
source volume is suitable. To replace the same name, withdraw the old folder first;
a brief unavailable view is acceptable. Do not assume a portable atomic rename
over an existing nonempty directory. Exposed files remain unchanged when a
coherent observation is required. In-place multi-file edits can be observed
while incomplete. Stable-read checks detect ordinary races; they are not
filesystem transactions and do not prove atomic multi-file publication.

## Security and runtime boundaries

The configured directory and its reader permissions are trusted deployment
settings. Read access is established from the caller's current verified
identity, never from the groups or admin flags in a viewed configuration.

Folder access permits reading the whole selected public project, including its
identity and broker documents. Deployments must segregate confidential projects
and assign the appropriate audience. Being an administrator of one organization
does not grant access to every folder on the server.

The viewer reads only recognized source indexes and their explicit references.
It does not serve arbitrary paths, import adjacent credentials, resolve
environment-secret references or contact endpoints named in preview files.
Operators must keep literal secrets out of the designated public source files.

Folder observation belongs to the operational Admin component outside Core.
Missing or invalid external viewer content does not make RPC/Core unready.
Core continues using its independently selected approved artifact and existing
loading process. Core hot reload is outside this decision.

Wallet linking, disclosure cases, travel-rule records and other actual
operational actions are separate from configuration viewing and remain intact.

## Cleanup decision

Remove obsolete V2 browser authoring code and its unused interfaces. Do not
revert the preceding UI work: retain the useful presentation, selection colors,
inspection dialogs, relationship displays, login, responsive header and
authorization protections. There will be no hidden editing mode, feature flag
or parallel legacy configuration workflow. Git history retains the removed code.

Keep external authoring tools, the Go validator/compiler, agent skills and the
approved-file loader. Remove only genuinely obsolete browser handoff tools;
shared V1 components and operational APIs are not removed as a side effect.

The concrete cleanup and verification sequence is in the
[implementation plan](../implementation/configuration-viewer-plan.md).
