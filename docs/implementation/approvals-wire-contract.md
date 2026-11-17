# Signed approval contract

The canonical wire, signature and receiver semantics are maintained in the
[OPS node integrations contract](https://github.com/gateway-fm/ops-node-integrations/blob/f9e039cbfabe82c3f8cc668d71fa437cde4856a0/docs/implementation/approvals-wire-contract.md).
The matching [fingerprint contract](https://github.com/gateway-fm/ops-node-integrations/blob/f9e039cbfabe82c3f8cc668d71fa437cde4856a0/docs/fingerprints.md)
describes strict and Calls V3 execution projections.

OPS consumes version 1.0.0 through the immutable commit and manifest hash in
[`integrations/approvals-contract.lock.json`](../../integrations/approvals-contract.lock.json).
The local protobuf and Go golden vectors are verified copies of that contract. See the
[contract update procedure](../../integrations/README.md) before changing them.

For deployment settings, trust keys, network isolation and recovery behavior, see the
[approval operator guide](https://github.com/gateway-fm/ops-node-integrations/blob/f9e039cbfabe82c3f8cc668d71fa437cde4856a0/node-approvals/OPERATIONS.md). The Reth demo builds its producer from the same
pinned commit; it moves to a checksum- or digest-pinned artifact once the integration repository
publishes a qualified release.

<a id="7-settings"></a>

## Settings

The [canonical settings table](https://github.com/gateway-fm/ops-node-integrations/blob/f9e039cbfabe82c3f8cc668d71fa437cde4856a0/docs/implementation/approvals-wire-contract.md#7-settings)
lists sender TTL, delivery bounds, receiver capacity, wait windows and trusted-key configuration.
