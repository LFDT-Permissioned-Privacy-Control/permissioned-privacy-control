# Immutable policy-bundle foundation

`internal/policybundle.LoadDirectory` validates a deployment-selected local
artifact and returns an immutable catalog. It does not replace the running
server's configuration source or establish production readiness. It imports
the native `policycore`, not the compatibility facade or optional EVM backend.

The deployment supplies the directory, expected manifest SHA-256, environment
and canonical decimal chain ID. Trusted code supplies positive resource limits,
`FoundationProfile(methodCatalogVersion)` and a version-matched method catalog.
The evaluator identity is `policycore/native-v1alpha1`; this names the existing
native semantics. Method names and aliases are exact, and `*` expands only the
trusted catalog's explicit wildcard set. Files cannot register methods.

The directory must contain `manifest.json` and exactly its listed regular
documents. Names are flat lowercase ASCII `.json` basenames, at most 128 bytes.
Symlinks, subdirectories and special files are rejected. Deployments must
materialize projected ConfigMap symlinks into regular files before loading.
Directory enumeration and reads are bounded. Root confinement and hashes do
not defend against a malicious deployment-filesystem owner: the artifact must
be delivered read-only by trusted deployment tooling.

The manifest uses `ops.policy-bundle/v1alpha1`, kind `PolicyBundle`, and contains
`environment`, `chainId`, `evaluatorVersion`, `profile`, `sourceRevision`,
`organizations`, `requiredCapabilities` and `documents`. Organizations have
`id`, `slug` and `name`. Document references have `kind`, `organizationId`,
`path` and `sha256`. Digests use `sha256:` plus 64 lowercase hex digits.
Source revision is metadata; the loader does not independently prove Git approval.

Each organization requires explicit `groups`, `contract-registry` and
`execution-rules` documents, using `ops.policy-document/v1alpha1`, with `kind`,
`organizationId` and a closed `spec`. Groups retain the existing static source
fields. Contracts retain ABI, privacy flags and read grants; event predicates
use `must_be`. Execution spec is exactly `{ "policy": ... }`, using the existing
native model. Legacy lifecycle fields, user/membership records, legacy migration
restrictions and bytecode artifacts are rejected rather than discarded.

The new envelope requires non-optional fields and explicit arrays, including
native `bindings` and `allow`; `[]` expresses deny-all. Existing native optional
fields remain optional, but explicit null, wrong-case fields, unknown fields and
recursive duplicate keys are rejected. Standalone `policycore.Parse` and the
legacy configuration format retain their previous omission behavior.

ABI JSON retains standard metadata annotations and exact numbers during
canonicalization. Array/tuple complexity is checked before ABI type construction.
The expanded-head budget also conservatively bounds materialized Go type
expansion, including fixed arrays of dynamic elements and nested tuple fields;
a one-word ABI head does not imply a small reflected type.
Duplicate method selectors or event topics, including equivalent duplicates and
conflicting indexed event layouts, are rejected to prevent ambiguous indexes.
Raw manifest/file digests, normalized document digests, canonical ABI digests
and full native-policy digests identify different things and remain separate.

The fixed `catalog-foundation/v1` profile accepts registered literal targets,
CALL/STATICCALL, exact/wildcard/empty-input selectors, scalar address/uint
predicates and native value/depth/caller bounds. It rejects target classes,
delegatecall/callcode/create forms, upgrade grants, live record getters,
unregistered EOA event literals and visible-to history flags. These require
separately implemented profiles; the foundation does not select release cuts.
The static dynamic-event-payload flag is accepted and recorded as a requirement.

Capabilities and scoped RPC credential references are inferred from actual
usage. The manifest capability set must match exactly: declarations cannot
enable unsupported features or conceal missing inputs. Secret references name
injected variables; the loader does not read environment values. A snapshot
cannot prove that principal, wallet, trace, secret or history providers exist.
Ordinary visible-to request handling remains a separate runtime contract.

Loading publishes nothing until every file, cross-reference, ABI pin, profile
and requirement validates. Failure returns no catalog. Accessors copy mutable
data; execution access exposes only the opaque validated native program. No
watcher, reload, persistent active pointer or last-good fallback is created.
Restart revalidates the selected image/bundle pair; deployment controls routing
and rollback.

Run the bounded checks with:

```sh
go test -race ./internal/policybundle ./internal/strictjson ./internal/configuration ./internal/policycore
go test ./internal/archtest -run 'Test(PolicyBundleDependencyBoundary|NativePolicyDependencyBoundary|DependencyDirection)$'
```
