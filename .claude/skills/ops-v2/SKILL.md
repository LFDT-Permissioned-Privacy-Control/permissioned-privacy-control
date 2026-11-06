---
name: ops-v2
description: Prepare, inspect and check Git-reviewed OPS V2 policy files with the local shared checker and offline editor. Use for V2 configuration authoring and access-rule diagnosis; use the ops skill for the V1 managed revision API.
---

# OPS V2 policy files

Use the complete source checkout matching the intended deployment. Read
[the authoring workflow](../../../docs/implementation/policy-authoring.md)
for commands, source shape and deployment limits. Paths below are relative to
the source root.

Run `go run ./cmd/ops-v2 policy profiles` before choosing a schema. Respect each
profile's evaluator version and validation-only status. Do not infer implemented
runtime handlers from a successful source check or a method's catalog membership.

Start from `examples/ops-v2-policy/` or the customer's existing source directory.
It contains `draft.json` and exactly its referenced regular JSON files. Edit
the approved-source model; do not create users, membership rows, SQL revisions
or bytecode artifacts. External verified facts map to configured groups; unknown
facts grant nothing. Keep credential values out of files: use supported secret
reference names.

For ABI-based rules, use `go run ./cmd/ops-v2 policy abi --file ABI.json`.
Use its `abiDigest` and canonical selector/signature results, not the original
file-byte hash or guessed identifiers. Anonymous event signature hashes cannot
be used as topic0 grant rules. Inspection does not verify deployed code ownership.

Prepare with `policy prepare --source DIR --output NEW_DIR --profile ID`.
Preparation derives hashes and capabilities using the same source compiler as
the runtime loader. Preserve intended restrictions when fixing errors; do not
add wildcard/admin/deploy/upgrade grants just to make a check pass. Existing
output paths are rejected; a failed attempt may leave a partial new directory.

Run `policy check` or `policy inspect` with explicit `--bundle`,
`--expected-digest`, `--environment`, `--chain-id` and `--profile`. Review the
exact source diff and artifact identities. A local digest reports what was
prepared; trusted review/deployment selection establishes which digest to use.
An adjacent untrusted digest file does not establish approval.

Report changed permissions, checker results and outstanding runtime requirements
plainly. Submit the Git change through the user's authorized review process.
Local checks and the static editor never approve or activate a policy. Do not
call legacy admin setters, a CI approval endpoint or an SDK activation workflow
as a substitute for Git review. The file workflow needs no published SDK.

The browser editor is optional: serve `tools/ops-admin-ui` locally as described
in the authoring workflow. Its syntax hints are preliminary; downloaded edits
must be saved to the intended source folder and checked with the Go tool.
