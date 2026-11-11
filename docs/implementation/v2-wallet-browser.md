# Native wallet ownership in the V2 browser

The central own-account panel and Explorer **Wallets** page use the same four
native operations: list own links, request an address-specific challenge,
verify its EIP191 signature, and revoke a link. Linking remains an operational
user action. It does not edit Git configuration, create a Core user record,
assign a group or authorize a transaction.

The central panel uses the original signed Core bearer. Explorer retains that
bearer only in its encrypted server-side app session. Both sign the exact
server message using `personal_sign` with UTF8 bytes encoded as hex. The
message binds the service, deployment namespace, Actor, address, nonce and
original expiry. Its literal `OPS wallet link v1` line is the message format;
the native ownership proof version is 2. The backend-owned service origin can
differ from the browser sign-in origin and is displayed without rewriting it.

Choose a wallet address, inspect the message, sign it, then explicitly confirm
the link. Signatures and nonce state remain in document memory. A rejected,
expired or uncertain operation is never automatically replayed. **Refresh links**
reads the current durable state before another action.

Unlink requires an explicit warning and confirmation. A revoked address cannot
be relinked to the same OPS identity under the current deployment rules. There
is no Undo endpoint. The own list contains only active native
`{address,verifiedAt,proofVersion:2}` entries; transaction-inferred system links
and V1 wrapped user records are not used.

The central controller performs one identity warm-up and verifies the own-self
response before creating a wallet operation. The resulting original token,
verified identity and expiry remain fixed across challenge, signature and
confirmation. Starting renewal retires wallet work before awaiting the helper.
Every relevant foreign browser-context event also clears wallet work, even when
a same-account renewal restores identical final marker bytes. Such events
invalidate proofs; they do not authenticate or adopt another identity.

The Explorer scope similarly fixes one app activation across provider and HTTP
awaits. Account changes, expiry and page suspension clear private wallet facts.
The BFF checks the original capture immediately before forwarding and before
private output. No lock spans the network: an already forwarded original-Actor
operation can commit while its response is withheld after a session change.

`wallethttp.Handler.RegisterLinks` registers the exact four required routes:

| Method | Route |
| --- | --- |
| GET | `/api/v2/eth/addresses` |
| POST | `/api/v2/eth/link/challenge` |
| POST | `/api/v2/eth/link/verify` |
| DELETE | `/api/v2/eth/addresses/{address}` |

The full `Register` method additionally exposes optional ENS refresh. A selected
composition without a qualified resolver uses `RegisterLinks`. The browser
panels and Explorer adapter provide no ENS lookup, ENS input or V1 wallet aliases.
Requests are limited to 8 KiB and responses to 1 MiB; native HTTP calls use a
five-second or earlier parent timeout. Mutations require known SQL COMMIT.
Own lookup completes a bounded ready-state SELECT and checks the live identity
before output; it is not a new read-COMMIT protocol.

The controlled browser integration uses the real identity broker, wallet service,
restricted operational SQL, built UIs and real EIP191 signatures behind an owned
injected-provider adapter. It tests protocol behavior, not a physical wallet
extension or a hosted identity-provider deployment. Concurrent SSO callback
responses retain their documented availability limit: an older delayed cookie
can require restarting sign-in, while durable capture checks fail closed.
