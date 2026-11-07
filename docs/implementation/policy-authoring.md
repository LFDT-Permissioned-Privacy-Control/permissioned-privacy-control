# Prepare and check policy files

The local `ops-v2 policy` commands prepare proposed artifacts and check exact
files with the same Go compiler used by `policybundle.LoadDirectory`. They do
not connect to OPS, approve a change, resolve credential values, or activate a
policy. Use the source release that matches the intended deployment.

## Start with a bounded draft

From the source root, list the compiled profiles:

```sh
go run ./cmd/ops-v2 policy profiles
```

The catalog foundation, identity, native V2 and disclosure profiles are **validation-only**.
The native V2 profile explicitly selects `policycore/native-v1alpha2`, including
`minDepth`; it does not change the older profiles' semantics. A passing source
check does not establish working identity providers, node tracing, linked wallets,
operational storage or a ready HTTP server.

Copy `examples/ops-v2-policy/` into a separate source directory. It is a
deliberately empty, deny-all example for the foundation profile. Add the intended
organizations, groups, contracts and execution rules using the closed source
schemas described in [the bundle foundation](policy-bundle-foundation.md).
For an identity-capable profile, also provide the global source described in
[the identity catalog](identity-catalog-foundation.md). Unknown facts grant no
groups; configuration does not contain user or membership rows.

`draft.json` uses `apiVersion: ops.policy-draft/v1alpha1`, kind `PolicyDraft`, and
contains `environment`, `chainId`, `evaluatorVersion`, `profile`,
`sourceRevision`, `organizations` and `documents`. Each document reference has
`kind`, `organizationId` and `path`. The optional `identityCatalog` has `path`.
Hashes and `requiredCapabilities` are derived by preparation. Do not add them to
the draft. `sourceRevision` is descriptive metadata, not proof of Git approval.

`catalog-runtime-call/v1` additionally requires `runtimeCatalog: {"path": ...}`
in the draft. The shared compiler pins its exact file bytes and infers the
runtime requirements. The profile report labels it as an **eth_call integration
slice**; a successful file check does not establish a complete server or qualify
its node, wallet and deployment providers. Other runtime operations require
their explicitly supported profiles. The older profiles reject this global file.

Keep only `draft.json` and its referenced JSON files in that flat source
directory. Files must be regular files with lowercase ASCII `.json` basenames;
symlinks and extra files are rejected. The default limits include 1 MiB per
document or manifest and 64 MiB for the artifact. The generated manifest's
hashes and inferred requirements count toward those limits.

The explicit `catalog-disclosure/v1` profile additionally requires a global
`disclosureCatalog` source. Its rules, case APIs and operational boundaries are
described in [disclosure cases](disclosure-cases.md). This profile does not
implicitly enable node tracing or protected report/data handlers.
The runtime-call and disclosure profiles reject each other's global source;
neither combines these capabilities into a complete runtime profile.

## Derive ABI identifiers

For an ABI obtained from the intended contract build, run:

```sh
go run ./cmd/ops-v2 policy abi --file ./contract-abi.json
```

`abiDigest` is the unprefixed SHA-256 of the registry's canonical ABI bytes;
use it for exact-selector execution rules. `fileByteDigest` identifies the exact
original file, while `canonicalByteDigest` identifies the normalized ABI with
the `sha256:` prefix. Whitespace or object key order can change the first without
changing the canonical digest. The tool returns canonical function signatures
and selectors, and event signature hashes. An anonymous event has no signature
in its emitted topic0, so its report omits `topic0` and sets
`topicRuleEligible: false`. Inspection does not prove that the ABI matches
deployed bytecode or grant permission to use a selector.

## Prepare a new artifact and inspect it

```sh
go run ./cmd/ops-v2 policy prepare \
  --source ./examples/ops-v2-policy \
  --output ./policy-artifact-local \
  --profile catalog-foundation/v1
```

The output directory must not exist. Preparation validates all sources, preserves
their exact bytes, derives file hashes and capabilities, writes a deterministic
`manifest.json`, then checks the completed output through the pinned loader.
It writes documents before the manifest using exclusive file creation, syncs
the files and output directory, and reports success only after the checked load.
An interruption may leave a partial **new** directory: use another new output
path or inspect and remove that partial output explicitly. This operation is
not an atomic publication protocol or a power-loss durability guarantee for
the parent directory. It never replaces a live directory or active pointer.

The JSON result includes `manifestDigest`, selected profile, inferred
requirements and document identities. `approved` stays `false`. Use the exact
digest selected by your review context for a subsequent check:

```sh
go run ./cmd/ops-v2 policy check \
  --bundle ./policy-artifact-local \
  --expected-digest sha256:REPLACE_WITH_THE_REVIEWED_64_HEX_DIGITS \
  --environment local --chain-id 31337 --profile catalog-foundation/v1
```

`policy inspect` takes the same flags and performs the same checked load. Never
take an expected digest solely from a file beside an untrusted artifact. Hashes
detect substitution only when the expected value comes from a trusted review
or deployment context. Review source changes and the exact generated artifact
in Git; a successful command is not an approval. The runtime loader requires
`manifest.json` and its listed files, without the authoring `draft.json`.

## Edit files locally in the browser

Serve only the static editor assets from the source root:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory tools/ops-admin-ui
```

Open `http://127.0.0.1:8765`, import the draft and its referenced source files,
edit, compare, and download each changed file into the intended source folder.
Unchanged downloads preserve original bytes, including line endings. Edits
produce new UTF-8 bytes and require a new checker run. Browser JSON syntax
hints are preliminary; the shared Go checker validates the complete rules.
The editor makes no OPS or Git requests and has no credential, approval or
activation action. Downloading a file does not save it into the Git checkout
automatically.

The repository's V1 revision SDK and MCP workflow remain separate tools for the
existing managed API. This file workflow needs neither a published SDK nor new
Core mutation endpoints. The [V2 authoring skill](../../.claude/skills/ops-v2/SKILL.md)
guides an agent through the actual local commands; the V1 skill remains available
for deployments using the older API.

## Deployment selection

Keep the approved Git revision, exact artifact manifest digest and compatible
image digest together in deployment configuration. Materialize the selected
artifact as regular read-only files. `LoadDirectory` revalidates the selected
hash, environment, chain, profile and all requirements on every startup; it
has no watcher or last-good database fallback. Deployment tooling must stop
routing traffic to an instance that fails startup validation.

DevOps drains and replaces instances deliberately. Different selected bundles
can authorize differently during a rolling deployment. Rollback selects a
previously approved compatible image **and** bundle, not an old binary paired
with arbitrary new files. These tooling commands do not provide a production
server launcher, provider qualification or fleet-wide atomic activation.

## Verification

```sh
go test -race ./internal/policybundle ./internal/policycli ./internal/policyprofiles ./internal/rpcmethoddata
go test ./internal/archtest
node --test tools/ops-admin-ui/model.test.mjs
```

`tools/ops-admin-ui/browser-smoke.mjs` additionally exercises real file input,
downloads, escaping and desktop/mobile layout with local Chrome and a loopback
server. It requires Node 24 and Chrome, uses its own temporary browser profile,
and writes screenshots/results into the directory passed as its first argument.
