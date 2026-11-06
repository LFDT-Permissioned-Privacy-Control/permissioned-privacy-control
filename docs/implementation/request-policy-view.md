# Selected-snapshot request policy view

`runtimepolicy.NewFactory(snapshot, clock)` owns an access verifier for the
selected bundle's identity catalog. `Build(rawAccessJWT)` verifies through that
exact verifier and captures one immutable request view. There is no constructor
that pairs an externally verified principal with a different policy snapshot.
A new factory recomputes mappings and policy facts under its selected bundle;
an existing view keeps its original diagnostic data.

The view carries actor, kind, original expiry and detached bundle metadata.
`RequireLive` checks that original expiry without renewal or changes to issued
Guard approvals. Authority-granting consumers must call it at their checkpoints;
diagnostic getters themselves remain readable after expiry. This library adds
no HTTP route, forwarding decision, provider lookup or operational store.

Each org view contains only groups mapped by verified facts in that org. It
unions their exact method names, keeps per-group source operational masks and
distinguishes true org admin from readonly admin and ordinary admin claims.
True org-admin groups have mask 7 while retaining their configured method set.
Readonly flags alone add no method, association or mask. Source masks are upper
bounds: they are not qualified target-specific `policycore.Frame.GroupClaims`.
Neither masks nor admin flags synthesize missing native execution rules.

`CatalogSnapshot.Method` returns copied raw/canonical names and the sorted
union of their required operational claims. An alias-only group grant does
not grant the canonical name. A known method entry is not evidence that a safe
operation or response handler exists and does not authorize passthrough.

The factory indexes registered contract owners once. Contract metadata is a
whitelist of ID, address, name, ABI and privacy flags, without grants or claims.
Read association/admin and filtered read grants are separate accessors scoped
to the registered owning org and mapped groups. Unknown addresses do not become
EOAs. Returned ABI, grants, rules and parameters are detached copies.

A ReadGrant with event mode `none` still records contract association; it grants
no event entitlement or native execution. `all` and `allowlist` remain explicit.
True org admin can supply owner-org read association/admin; an ordinary admin
claim needs a matching read association. A foreign admin or readonly flag cannot
supply it. Scalar/storage, transaction-row, event-field and execution decisions
remain distinct; this view does not evaluate or forward a request.

Credential accessors return approved reference names from mapped groups in one
org, optionally restricted to the exact raw method grant. Equal references
coalesce; selecting multiple distinct references returns `AmbiguousCredential`.
No environment lookup, decryption, plaintext fallback or first-group selection
occurs. Response org unions never choose upstream credentials.

The view contains no user UUID, membership/resolver/cache fallback or broad
`rbac.Store`. Actual request floors, target evidence, native evaluation and
shared response filtering consume these facts through their separate runtime
interfaces. A library view alone is not a production authorization service.

```sh
go test -race ./internal/runtimepolicy ./internal/policybundle
go test ./internal/archtest -run 'Test(RuntimePolicyDependencyBoundary|PolicyBundleDependencyBoundary|IdentityDependencyBoundary)$'
```
