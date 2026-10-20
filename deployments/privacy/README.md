# Privacy-mode deployment

This folder holds the artifacts that make up the **privacy-mode**
deployment of the Open Privacy Suite. If you're running corporate /
permissioned-chain workloads and care about the privacy guarantees the
product advertises, this is the deployment you want.

The authoritative manifest is `docker-compose.privacy.yml` at the
Open Privacy Suite repo root. Everything else in this folder is config
referenced by that manifest.

## Why this deployment exists — RD-855 in one paragraph

Prior to RD-855, the suite was deployed such that **Open Privacy Suite was not
a chokepoint**. The block-explorer ran its own api service, its own
postgres, and its own indexer alongside Open Privacy Suite; anything that could
reach the block-explorer's exposed surface could pull raw chain data that
should have been redacted. The privacy-mode deployment in this folder
fixes that structurally: the components that had direct access to raw
data are not deployed at all. There is no filter-based guard to get
wrong. See `docs/rd-855-behavioral-shifts.md` for the handful of
endpoints that degrade in privacy mode as a consequence.

## Trust boundary

```
   +-------- indexer-zone (internal) --------+   +------ bff-zone (internal) -------+
   |                                         |   |                                  |
   |  anvil / EVM node                       |   |  block-explorer-api (BFF,        |
   |       \                                 |   |  privacy-tagged build)           |
   |        --> chain-indexer                |   |          |                       |
   |              \                          |   |          v                       |
   |               --> indexer-postgres      |   |  block-explorer-postgres         |
   |                                         |   |  (verifications only)            |
   |  privacy-postgres   redis               |   |                                  |
   |       ^                ^                |   |          ^                       |
   |       |                |                |   |          |                       |
   +-------|----------------|----------------+   +----------|----------------------+
           |                |                               |
           +-------+--------+              +----------------+
                   |                       |
                   v                       v
                +---- proxy-backend (Open Privacy Suite) ----+
                |   sole bridge across all three        |
                |   zones. Applies RedactionEngine.     |
                +---------------------------------------+
                                |
                                v
       +---------------- public --------------------+
       |                                            |
       |  proxy-frontend (admin UI)                 |
       |  block-explorer-frontend (nginx + SPA;     |
       |    also attaches to bff-zone to reach      |
       |    the BFF)                                |
       |                                            |
       +--------------------------------------------+
                                |
                                v
                            Clients
```

**Rules:**

1. **proxy-backend (Open Privacy Suite) is the only service that legitimately
   attaches to both internal zones.** It is the sole network path
   between bff-zone and indexer-zone. The static manifest test enforces
   this by name (`e2e.BridgeService`); adding any other cross-zone
   service requires updating the test AND justifying the cross-zone
   path.
2. **The indexer listens on indexer-zone only.** Its gRPC port is not
   published and no ingress points at it. Open Privacy Suite is the sole
   consumer. The block-explorer BFF — even though it is also a
   "trust-zone" service in the broad sense — has no route to indexer-zone.
3. **The block-explorer BFF lives in bff-zone, not indexer-zone.** The
   BFF terminates the OAuth flow, owns browser sessions (HttpOnly
   cookies), stores contract verifications, and forwards chain-data
   reads to Open Privacy Suite so redaction applies. Even if a future PR
   drops the BFF's `--target privacy` build tag or sets `INDEXER_URL`,
   the BFF still cannot reach the indexer because the network forbids
   it. This makes the network the structural floor for defense-in-depth
   (independent of the BFF's compile-time and runtime defenses — see
   the "Block-explorer BFF" section).
4. **No block-explorer indexer is deployed.** The chain-indexer owns the
   only chain-data store in the deployment.
5. **Frontend nginx routes `/api/*` to the BFF and returns 404 on
   `/ws`.** The runtime config is `deployments/privacy/nginx.privacy.conf`,
   mounted into the block-explorer-frontend nginx container at startup.
   The frontend attaches to bff-zone (to reach the BFF) and public (so
   clients can reach it) — it has no path to indexer-zone.

## What's deployed vs. what isn't

| Service | Deployed | Zone | Host-published? |
|---|---|---|---|
| privacy-postgres | ✅ | indexer-zone | no |
| redis | ✅ | indexer-zone | no |
| anvil (EVM node, dev) | ✅ | indexer-zone | no |
| chain-indexer | ✅ | indexer-zone | no |
| indexer-postgres | ✅ | indexer-zone | no |
| proxy-backend (Open Privacy Suite) | ✅ | indexer-zone + bff-zone + public (bridge) | yes |
| proxy-frontend | ✅ | public | yes |
| block-explorer-frontend | ✅ | bff-zone + public | yes |
| **block-explorer-api (BFF, privacy build)** | ✅ | bff-zone | no |
| **block-explorer-postgres (verifications only)** | ✅ | bff-zone | no |
| **block-explorer indexer** | ❌ | — | — |

## Running it

There are two compose files for privacy mode and they are **siblings,
not base/overlay**. Pick one — do not stack them.

```bash
# Production manifest. Mock auth disabled, ENVIRONMENT=production,
# all services pulled from published registry images (no local build),
# anvil ports not published.
docker compose -f docker-compose.privacy.yml up -d
```

```bash
# Dev manifest. Mock auth on, anvil host port published, proxy-backend
# built from --target dev with ENVIRONMENT=development. Use this only
# for local development.
scripts/privacy-dev-up.sh
```

`scripts/privacy-dev-up.sh` is the one-command path: it generates
fail-closed secrets in `.env.privacy.dev`, validates that the sibling
repos exist, forces a `--no-cache` rebuild of the frontend so
`VITE_ALLOW_MOCK_LOGIN=true` is baked into the JS bundle, and waits for
the backend healthcheck. Delete `.env.privacy.dev` to rotate.

It also symlinks `.env -> .env.privacy.dev`. Docker Compose only
auto-loads a file named `.env` for `${VAR}` interpolation, so without
this any `docker compose up` outside the script — including **Docker
Desktop's start/play button**, which re-runs `up` rather than a bare
`docker start` — trips the fail-closed guards. With the symlink, the UI
start/stop buttons and a plain `docker compose -f
docker-compose.privacy.dev.yml up` work directly. Note the `.env` is then
picked up by *every* compose file in the repo root (base, prod, scale,
e2e); the script never overwrites a pre-existing real `.env`, it just
prints how to opt in.

Required env vars (all fail-closed — missing → compose aborts):

- `JWT_SECRET`, `JWT_REFRESH_SECRET` — Open Privacy Suite signing keys.
- `ADMIN_API_TOKEN` — initial admin token for bootstrap.
- `PRIVACY_POSTGRES_PASSWORD` — Open Privacy Suite's postgres.
- `INDEXER_POSTGRES_PASSWORD` — chain-indexer's postgres.
- `REDIS_PASSWORD` — Open Privacy Suite's redis.
- `BLOCK_EXPLORER_POSTGRES_PASSWORD` — BFF's postgres (verifications).

Optional env vars (have sane defaults):

- `HOST_BIND` — interface the published host ports bind to. Defaults to
  `127.0.0.1` (loopback only). Set to `0.0.0.0` if you need LAN access
  from another device; never do this on a production host without an
  upstream firewall.
- `HOST_PORT_PROXY`, `HOST_PORT_UI`, `HOST_PORT_EXPLORER` — host ports
  for the proxy API, admin UI, and explorer UI respectively. Defaults
  `8080` / `5173` / `3001`.
- `CORS_ALLOWED_ORIGINS` — comma-separated list of additional origins
  the proxy should accept on browser requests and OAuth redirects. The
  origin derived from `BASE_URL` is always allowed; this is for extra
  origins (e.g. `https://explorer.example.com`).
- `PROXY_VERSION` — registry tag for `gatewayfm/privacy-proxy-{backend,frontend}`.
  Defaults to `latest`. Pin to a tagged release in production
  (e.g. `PROXY_VERSION=v0.7.0`).
- `EXPLORER_VERSION` — registry tag for the block-explorer images
  (`gatewayfm/block-explorer-api-privacy` and
  `gatewayfm/block-explorer-frontend`). Defaults to `latest`. Note the
  `-privacy` suffix on the API image: block-explorer publishes a
  separate explicit privacy build alongside the standalone variant
  (block-explorer PR #66 / RD-922). The privacy compose pulls only
  the privacy-tagged API image; the standalone image is for non-privacy
  deployments. Same pinning advice as `PROXY_VERSION`.
- `INDEXER_VERSION` — registry tag for `ghcr.io/gateway-fm/chain-indexer`.
  Defaults to `latest`.
- `BLOCK_EXPLORER_PATH`, `CHAIN_INDEXER_PATH` — only consumed by the
  sibling **dev** compose (`docker-compose.privacy.dev.yml`), which builds
  from local clones. Default to `../block-explorer` and `../chain-indexer`.
  Ignored by the prod manifest above.
- `ENABLE_OP_DEPOSITS` — toggle OP-Stack indexing in the chain-indexer.

## What not to do

- **Do not stack this manifest with `docker-compose.yml` or
  `docker-compose.prod.yml`** (`docker compose -f docker-compose.yml -f
  docker-compose.privacy.yml up`). The non-privacy files reintroduce
  services (notably the `shared` network) that would let block-explorer
  components join and re-open the bypass path. If someone wants a hybrid
  deployment, they should say so explicitly and work out a bespoke
  compose; there's no supported hybrid.
- **Do not add an ingress rule for `chain-indexer:50051`** — if clients
  can reach the indexer directly, redaction is bypassed. There is no
  legitimate use case for external indexer access in privacy mode.
- **Do not mount the block-explorer repo's own nginx config** into the
  `block-explorer-frontend` container — it routes WS and `/api/*` to
  a service name (`api`) that doesn't exist in this compose, and does
  not know about the `/ws → 404` privacy-mode rule. The privacy-mode
  config in `deployments/privacy/nginx.privacy.conf` is the
  authoritative one.
- **Do not deploy `block-explorer-api` from an image built without
  `--target privacy`.** The default (standalone) build image links
  the chain-indexer gRPC client; with network egress to the indexer
  it would bypass redaction. The compose uses `target: privacy` for
  exactly this reason.

## Block-explorer BFF

Block-explorer in privacy mode runs as frontend **plus a thin
Backend-for-Frontend (BFF)** — `block-explorer-api`. A pure-SPA
deployment can't terminate OAuth against Open Privacy Suite (no place for
`/api/auth/callback`, no HttpOnly cookie setter, nowhere to persist
contract verifications); putting the access token in JavaScript would
fail OWASP ASVS L2+ and OAuth-for-Browser-Based-Apps BCP. So we run a
minimal server whose only job is session management + proxying.

The BFF's only legitimate chain-data source is Open Privacy Suite. Three
layers of mutually-independent defense keep it that way:

| Layer | Mechanism |
|---|---|
| Compile-time | BFF image is built with `go build -tags privacy` via Dockerfile `--target privacy`. The `indexerclient` package (chain-indexer gRPC client) is excluded at compile time; the resulting binary has no code path that can speak chain-indexer gRPC. Verifiable with `strings` on the image. |
| Runtime | `cmd/api/provider_privacy.go` in block-explorer `log.Fatal`s on startup if `INDEXER_URL` is set, or if `PRIVACY_PROXY_URL` is empty. |
| Network | `block-explorer-api` sits on `bff-zone` only; `chain-indexer` sits on `indexer-zone` only. The two are different docker networks. **The BFF physically cannot reach the indexer** because there is no route. proxy-backend (the bridge) is the only service attached to both zones, and it applies RedactionEngine on every chain-data response. |

These layers fail independently. A future PR that drops the
`--target privacy` stage from the BFF Dockerfile breaks layer 1 — and
the network layer still holds. A future PR that adds `INDEXER_URL` to
the BFF's environment in compose breaks layer 2 — and the network layer
still holds. The structural floor survives upstream build-pipeline
mistakes.

The BFF's postgres (`block-explorer-postgres`) holds only
contract-verification artifacts — user-submitted source code and ABIs.
No chain data. bff-zone only.

## Trust model: no auth between internal services

The privacy-mode deployment does **not** place application-level
authentication on the internal service-to-service hops:

- `Open Privacy Suite → chain-indexer` gRPC is plaintext, no mTLS, no bearer token.
- `Open Privacy Suite → privacy-postgres` uses password-only `sslmode=disable`.
- `Open Privacy Suite → redis` uses a shared password on the compose network.
- `chain-indexer → indexer-postgres` uses the same pattern.
- `chain-indexer → anvil` (or prod RPC) is plaintext.
- `block-explorer-api → Open Privacy Suite` is plaintext; the BFF is a
  client like any other, subject to OAuth/JWT for per-user authz.
- `block-explorer-api → block-explorer-postgres` uses password-only
  `sslmode=disable`.

This is **intentional**. The trust boundary is enforced at the
**network level**, with two zones:

1. Internal services live on one of two dedicated docker networks
   (`indexer-zone`, `bff-zone`) with no host-port publishes.
   `docker-compose.privacy.yml` deliberately omits `ports:` on every
   internal service.
2. `proxy-backend` is the **only** service permitted to attach to both
   internal zones. The block-explorer BFF lives in bff-zone only and
   has no route to chain-indexer in indexer-zone.
3. `e2e/privacy_manifest_test.go` (static, PR-gated) fails the build
   if any internal service sprouts a `ports:` block, if a listed
   public service loses its publish, or if any service besides
   `proxy-backend` attaches to both internal zones.
4. `e2e/privacy_bypass_test.go` (runtime, weekly) brings the full
   stack up, verifies internal-zone ports are unreachable from the
   host, AND probes from a throwaway container on bff-zone that
   `chain-indexer:50051` is unreachable across the zone boundary.
5. `deployments/privacy/trust-zone.yaml` is the single source of truth
   for which services are in which zone; both tests load it.

**Implication for operators** deploying outside compose (Kubernetes,
other orchestrators): you must preserve this two-zone network isolation
(see the "Deploying outside compose" section below for a concrete
NetworkPolicy example). Do not expose `chain-indexer`, `*-postgres`,
`redis`, or `block-explorer-api` to any ingress, load balancer, or
service-mesh gateway. If a future target can't provide network
isolation, mTLS + bearer auth on each internal hop is the follow-up
work; that is deliberately **not** in scope for the compose-based
deployment.

**Why no defense in depth here?** Adding tokens on internal hops
without network isolation is cargo-cult security — an attacker who can
reach those services can already read the token from any compromised
container. Adding tokens *with* network isolation is genuine
defense-in-depth, but the token rotation / distribution cost isn't
justified at this stage. Revisit if we gain multi-tenant trust-zone
deployments where a compromise of one tenant's Open Privacy Suite should
not give access to another tenant's indexer.

## Known gaps (see behavioral-shifts doc)

A few endpoints degrade gracefully in privacy mode vs. standalone. The
full list with rationale and suggested fixes lives at
`docs/rd-855-behavioral-shifts.md`. Highlights:

- Dashboard "Total txs" / "Total addresses" reflect network-wide counts,
  not per-viewer filtered counts. (Arguably correct product behavior.)
- Offset pagination totals on log / transfer / internal-tx list views
  show page-local counts, not DB-wide totals.
- `/transfers` (unfiltered global transfer feed) is not available.
- `/ws` returns 404. Subscriptions are deferred.

(Contract verification is available via the BFF; ABI / source / verified
status render on the contract detail page as in standalone mode.)

## Testing the boundary

An automated negative-network test verifies the trust boundary is closed.
It brings up the full compose, asserts trust-zone services are not
reachable from the host, and asserts the frontend's routing behavior.

Run locally:

```bash
# Requires chain-indexer and block-explorer cloned as siblings of
# Open Privacy Suite. Takes 1-2 minutes.
make test-privacy-bypass
```

Run in CI:

The test lives in `e2e/privacy_bypass_test.go` (build-tag gated to
`privacy_bypass`, so it stays out of the default test run and pre-push
hook). A dedicated GitHub Actions workflow runs it on a weekly schedule
and on manual dispatch — see `.github/workflows/privacy-bypass.yml`.
Dispatch it manually after any change to:

- `docker-compose.privacy.yml`
- `deployments/privacy/nginx.privacy.conf`
- The block-explorer or chain-indexer Dockerfiles
- The indexer gRPC service surface

What the test asserts:

1. Compose config does not publish any trust-zone service's ports
   (structural: parses `docker compose config --format json`).
2. After `up`, each trust-zone service's default port is NOT reachable
   from `127.0.0.1` — a TCP connect times out or is refused.
3. `proxy-backend`, `proxy-frontend`, and `block-explorer-frontend`
   ARE reachable (positive check — these are intentional).
4. Block-explorer frontend's `/ws` returns `404` (standalone config
   would have proxied to a local subscription endpoint; a 502 or a
   successful upgrade indicates the wrong nginx config was mounted).
5. Block-explorer frontend's `/api/*` is routed to `block-explorer-api`
   (the BFF) — any well-formed HTTP status other than `502` or `503`,
   which would mean the wrong nginx upstream.

Manual spot-check recipe (sanity, not a replacement for the test):

```bash
nc -zv <host> 50051               # chain-indexer gRPC — should fail
nc -zv <host> 5432                # postgres(s)        — should fail
nc -zv <host> 6379                # redis              — should fail
```

## Deploying outside compose (Kubernetes, Terraform, etc.)

`docker-compose.privacy.yml` is a **reference deployment**. Ops teams
typically translate it to their orchestrator. That's expected — what
must survive the translation are the invariants, not the tooling.

Invariants (source of truth: `trust-zone.yaml`):

1. The host-exposed service list matches the `public:` section
   verbatim. Every service in `indexer_zone:` and `bff_zone:` has no
   ingress, no load balancer, no NodePort.
2. **The two-zone network split is preserved.** `indexer_zone:` and
   `bff_zone:` services translate to two independent
   network-policy domains. `proxy-backend` is the only service that
   may attach to both. The block-explorer BFF must NOT be able to
   reach the chain-indexer at the network layer, even if its
   compile-time `--target privacy` build tag is later dropped.
3. `block-explorer-api` runs the privacy-tagged image
   (`... --target privacy` on the Dockerfile, or `-tags privacy` for a
   `go build`). Without this the compile-time defense is off — but the
   network split (invariant 2) still holds.
4. `nginx.privacy.conf` is the active nginx config on the
   `block-explorer-frontend` pod (typically mounted from a ConfigMap).
   If ops write their own nginx config, it must preserve two rules:
   `/api/*` → the BFF service, `/ws` → 404.
5. All fail-closed env vars (`${VAR:?…}` list in the compose file) are
   sourced from a secret store (K8s Secrets, AWS Secrets Manager,
   etc.) — missing must prevent startup.

Our PR-gated + weekly tests validate the compose deployment.
**Equivalent coverage is required in ops' own infra**: a cluster-
internal probe that TCP-connects from outside each internal-zone pod's
allowed caller set and expects refused. Run it on deployment and on a
schedule; file the result as an audit control. `trust-zone.yaml` is
machine-readable on purpose — generate the NetworkPolicy YAML and the
probe targets from it rather than maintaining parallel lists.

### Kubernetes NetworkPolicy mapping

The two-zone split maps cleanly to K8s `NetworkPolicy`. There's no
direct docker-network equivalent (pod-to-pod is flat by default), but
NetworkPolicy is the structural control surface. With two zones, each
policy is "allow same-zone, deny everything else" — much harder to get
wrong than a single-zone policy that has to enumerate every allowed
caller.

```yaml
# All pods in one namespace; zones are pod labels. Open Privacy Suite carries
# both zone labels and is the only legitimate bridge.

# Indexer-zone services
apiVersion: v1
kind: Pod
metadata:
  name: chain-indexer
  labels:
    zone: indexer
# (also: indexer-postgres, anvil/EVM, privacy-postgres, redis)

# BFF-zone services
apiVersion: v1
kind: Pod
metadata:
  name: block-explorer-api
  labels:
    zone: bff
# (also: block-explorer-postgres)

# Open Privacy Suite — the bridge. Carries both labels.
apiVersion: v1
kind: Pod
metadata:
  name: proxy-backend
  labels:
    zone: indexer
    zone-bff: "true"   # K8s labels can't repeat keys; use a second key
                       # or use selectors with matchExpressions

# Public-only pods
apiVersion: v1
kind: Pod
metadata:
  name: proxy-frontend
  labels:
    zone: public
# (also: block-explorer-frontend, but it also needs zone-bff so its
#  nginx can reach the BFF)

---
# NetworkPolicy: indexer-zone — only zone=indexer pods (i.e. the indexer
# itself, its postgres, the EVM node, privacy-postgres, redis, and
# Open Privacy Suite) may ingress to indexer-zone pods.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: indexer-zone
spec:
  podSelector:
    matchLabels:
      zone: indexer
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              zone: indexer

---
# NetworkPolicy: bff-zone — only zone-bff pods (BFF, BFF-postgres,
# block-explorer-frontend, and Open Privacy Suite) may ingress to bff-zone
# pods.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bff-zone
spec:
  podSelector:
    matchLabels:
      zone-bff: "true"
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              zone-bff: "true"
```

**CNI prerequisite:** NetworkPolicy enforcement requires a CNI that
implements it — Calico, Cilium, weave-net with policy enabled, etc.
Flannel without `--network-policy` accepts policies but **does not
enforce them**. Verify with `kubectl get networkpolicy` and a probe pod
attached to the wrong zone trying to reach a zone-restricted service —
the connect must fail. Without enforcement the structural floor we
designed for in compose disappears at deploy time.

**Service mesh additivity:** if Istio or Linkerd is in play, layer
`AuthorizationPolicy` (Istio) or `ServerAuthorization` (Linkerd) on
top to enforce SPIFFE-identity gates. That gives you "only the
Open Privacy Suite ServiceAccount can call chain-indexer" — strictly
stronger than label-based NetworkPolicy because labels are mutable but
SPIFFE identities are not. Compose cleanly with the two-zone shape;
optional, not required.

## Relationship with standalone mode

**Standalone mode** remains supported via the existing `docker-compose.yml`
in the block-explorer repo. In that deployment:

- block-explorer api + postgres + indexer are all present.
- Contract verification works.
- WS subscriptions work.
- There is no Open Privacy Suite; data is public by intent.

Privacy mode and standalone mode share the frontend SPA bundle but route
through different nginx configs at container start.
