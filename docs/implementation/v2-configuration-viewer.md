# Admin configuration viewer

Admin shows configuration files supplied by an external system. Open **RBAC →
Configurations**, then choose a folder. Organizations, groups, contracts,
permissions, execution rules and identity mappings follow that configuration
throughout the dashboard. Choose another folder to inspect a different setup.
The structured views keep the normal Admin presentation; the original public
JSON files are also available for read-only inspection.

Opening a folder changes only the display. It does not approve or deploy files,
change the running policy or grant the current person any privileges. Admin has
no configuration editor, local file import, draft save/export, diff viewer,
validation-report import, approval or publication button. Configuration changes
and approvals happen outside Admin. Use the matching [Go authoring and checking
commands](policy-authoring.md) when preparing files for deployment.

Wallet linking, disclosure cases, compliance records, Access Logs and diagnostics
are separate operational features and keep their real authorization rules.

## Configure the server directory

Add the optional viewer section to the trusted operational server configuration
and select that configuration through its normal digest-pinned startup process:

```json
{
  "configurationViewer": {
    "directory": "/etc/ops/public-configurations",
    "layout": "folders",
    "audience": {
      "ownerOrganizationIds": ["11111111-1111-4111-8111-111111111111"]
    }
  }
}
```

This is a section of `ops.server/v2`, not a complete server file. Mount the
directory read-only in OPS. The external publisher needs its own write access.
Without this setting the viewer reports that no source directory is available;
it does not fall back to the approved runtime bundle or browser file uploads.

Choose the layout explicitly:

```text
single: /etc/ops/public-configurations/draft.json
    or: /etc/ops/public-configurations/core/draft.json
        /etc/ops/public-configurations/broker/draft.json

folders: /etc/ops/public-configurations/current/core/draft.json
         /etc/ops/public-configurations/current/broker/draft.json
         /etc/ops/public-configurations/proposed/core/draft.json
         /etc/ops/public-configurations/proposed/broker/draft.json
```

With `folders`, each immediate child is a configuration tab. Named `core` and
`broker` roots stay inside one configuration and have their own root selector.
The viewer reads `draft.json` and exactly its referenced public JSON documents,
including explicitly pinned broker contexts. Compiled runtime `manifest.json`
artifacts are a separate format and are not a fallback. There is no recursive
Git discovery, branch cloning or Git connection.

Candidate and named-root folder names use lowercase ASCII letters, digits,
underscores and hyphens, begin with a letter/digit and contain at most 64
characters. An external branch named `feature/example` must be materialized
under a safe single folder name such as `feature-example`. Referenced files use
flat lowercase JSON basenames. The reader bounds the catalog to 128 candidates,
each project to 16 roots and 2,048 input files, each file to 1 MiB and total raw
source to 64 MiB. It does not recursively scan an arbitrary checkout.

## Who can read a configuration

The viewer uses the signed-in person's current verified roles from the running
deployment. Permissions written in a viewed folder cannot authorize its reader.
Access requires a verified human admin or read-only admin, plus either:

- An admin/read-only-admin role in **every** configured owner organization,
  with at least one owner organization configured.
- An actor ID explicitly included in `operatorActorIds` in the trusted audience.

An empty audience grants nobody access. Optional `folderAudiences` entries
replace the default audience for named child folders; otherwise new children
inherit the directory's audience. Owners are existing deployment organizations,
not organizations inferred from the files under review. An authorized owner can
therefore inspect a configuration introducing a new organization.

Access covers the **whole** public project, including its identity and broker
catalogs. Separate confidential projects into appropriately scoped directories
or folder audiences; being one bank's administrator does not permit reading
every folder. Keep literal secrets out of designated public source files. The
viewer does not open adjacent credentials, resolve environment references or
contact nodes/providers named by the viewed files.

## External updates and removal

While a configuration view is visible, Admin refreshes the folder list and
selected contents automatically, and refreshes on focus. **Refresh** forces a
fresh read. Selection stays across configuration-page navigation. A single
configuration can open initially; after the selected folder disappears, the
view clears and another folder is never selected silently.

Valid updates replace the captured project as one unit. Open details use the
updated record or close when it disappears; records without stable IDs close
on an update. Unreadable, incomplete or unauthorized content clears old data
and shows a simple error. Logout, expiry or account/role changes also clear
protected content. Unsupported shapes or unsafe numeric values remain available
as raw source rather than being displayed as a rounded or altered permission.

For coherent multi-file publication, stage a complete folder outside the watched
directory on the same filesystem, then rename it to an absent candidate path.
For the same name, withdraw the old folder first, then expose its replacement;
a brief unavailable view is acceptable. Leave exposed files unchanged when
coherent observation is required. In-place edits have only best-effort race
detection; double reads do not create filesystem transactions.

The viewer keeps only bounded current observations for efficient refresh, with
no revision store or history. It does not indicate which candidate is running.
Core continues loading its separately approved, digest-pinned artifacts at
startup. A missing or malformed viewer folder does not make RPC/Core unready.

The read-only operational endpoints are `GET /api/v2/configuration/sources` and
`GET /api/v2/configuration/sources/{id}`. They enforce the same audience and
original credential expiry on fresh and conditional responses. There is no
arbitrary-path, upload or write endpoint.
