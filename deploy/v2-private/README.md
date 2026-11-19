# Native V2 private Indexer network

`compose.yml` defines the native OPS, Explorer BFF, creation observer and
Indexer backend networks. Select immutable runtime images and supply the
approved configuration volumes and restricted environment files before start.
Attach the existing Admin/Explorer ingress to `front`; preserve the public
origins and Host headers declared in the approved configuration. The Explorer
BFF listens internally; its frontend/HTTPS ingress is configured separately.

The Indexer has no login or viewer permissions. Its gRPC listener binds the
`indexer-api` interface, and only OPS joins that network. It does not listen on
its node-facing or storage-facing interfaces. No Indexer or database port is
published to the host. The Indexer database is on a separate network that OPS,
Explorer and the observer do not join.

The internal networks use Docker's `isolated` gateway mode, which requires
Docker Engine 28 or later. A network name or `internal: true` alone is not the
acceptance test: the numeric-IP negative checks must pass. This also keeps
Explorer away from the local node RPC and other services' database networks.
The `chain` network is for an in-network private node. For an external node,
adapt that connection to the operator's private network and rerun the gate;
do not publish the node RPC to make it reachable.

OPS calls `chain_indexer.v2`; it receives no Indexer database credential. The
Indexer-only environment file selects its database and node. OPS retains its
separate operational stores. Explorer retains its own application-session
store. These databases contain no copied blockchain index.

Set these image selections:

- `OPS_V2_IMAGE`: native OPS runtime, built from `Dockerfile.v2`.
- `OPS_INDEXER_IMAGE`: Indexer image containing the V1 and V2 gRPC services.
- `OPS_EXPLORER_IMAGE`: native privacy-tagged Explorer BFF.

The environment-file variables in the manifest are explicit and required.
Keep owner environment files for the three database clusters separate from
the serving environment files. Serving configuration volumes are read-only.
The configured OPS TLS port must match `OPS_V2_TLS_PORT`; the public host port
is selected separately with `OPS_V2_HOST_PORT`. Configure the selected Indexer
endpoint in OPS as `indexer-api:<OPS_INDEXER_GRPC_PORT>`.

The Indexer must not join a shared application network with a listener bound
to all interfaces. Preserve the network memberships when adapting the
manifest to another orchestrator. In Kubernetes, enforce a per-port ingress
policy for the Indexer gRPC port that permits only OPS pods; database ingress
permits only Indexer pods. Namespace labels alone do not isolate traffic.

## Finite network check

`scripts/check-v2-indexer-network.mjs` reuses the local demo provisioner with
fresh state, the production network memberships and normal runtime
entrypoints. `test-fixture.yml` adds the real Reth chain and offline provisioner.
It does not convert or copy a running demo's databases or activity spool.

Select already built images through `OPS_V2_NETWORK_OPS_IMAGE`,
`OPS_V2_NETWORK_EXPLORER_IMAGE`, `OPS_V2_NETWORK_INDEXER_IMAGE` and
`OPS_V2_NETWORK_TOOLS_IMAGE`, then run:

```sh
node scripts/check-v2-indexer-network.mjs
```

The check requires Docker, Go and the existing hash-checked Privado circuits
under `.tmp/v2-circuits`. It makes no image pull or browser installation.
It records immutable image IDs, actual service IDs, interface addresses and
the numeric-IP connection matrix under `.tmp/v2-network/<project>/`.

OPS must complete a real Indexer gRPC call. OPS and Explorer BFF readiness
must succeed using their normal processes. Explorer, the observer and other
service namespaces must fail to connect to every Indexer interface. OPS must
also fail to connect to the Indexer database. This proves connectivity of the
actual namespaces; application privacy and paging are tested separately.

The host-network local walkthrough remains a public test fixture. Its
restricted database credentials do not prove this network boundary.
