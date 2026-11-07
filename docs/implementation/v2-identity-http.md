# V2 identity HTTP and browser helper

`internal/identityhttp` wraps the concrete approved Azure broker, without a user
directory or mutable policy API. `New` requires the same selected manifest,
identity catalog, broker catalog and deployment Origin as the service. The
standalone `catalog-broker/v1` profile remains distinct from RPC runtime profiles.
This adapter and the helper are available for composition; the legacy server
and frontend entry point do not mount them automatically.

## Hosting and routes

Host the UI and API at one canonical HTTPS Origin. HTTP requires exact `Host`;
browser POSTs also require exactly one matching `Origin`. Forwarded headers are
not trusted. The approved human redirect must be
`<origin>/auth/azure/callback`: the browser page receives the query code/state
and POSTs them to completion. Completion URI is a clean same-origin path.
No backend GET endpoint redeems an authorization code.

| Method and path | Closed request | Result |
| --- | --- | --- |
| GET `/api/v2/auth/providers` | No query/body | Approved human profile IDs, fixed provider/kind labels and completion path |
| POST `/api/v2/auth/azure/start` | `{profileId}` | `{authorizationUrl,expiresAt}` after pending-state commit |
| POST `/api/v2/auth/azure/complete` | `{state,code}` | Human access result and HttpOnly renewal cookies after known commit |
| POST `/api/v2/auth/renew` | `{mode:"bootstrap"}` or `{mode:"renew",expectedActorId,expectedSessionId}` | Fresh provider grant, access result and rotated cookies |
| POST `/api/v2/auth/logout` | `{expectedActorId,expectedSessionId}` | 204 and cleared cookies only after known revoke |
| POST `/api/v2/auth/service/exchange` | `{profileId,upstreamAccessToken}` | Service access result, without a family or cookie |

Machine exchange accepts no `Origin` and no broker cookies. Service profiles
are excluded from browser provider choices. Unknown fields, duplicates, case
aliases, null substitutions, API query strings, encoded route aliases and
unsupported methods reject. JSON requires UTF-8 and `application/json` with
optional UTF-8 charset; compression is rejected. Start/renew/logout bodies are
limited to 2 KiB, completion to 12 KiB and machine exchange to 40 KiB. All
routes share 32 immediate admission slots; excess work receives 503 without a
queue. This is not an IP rate limiter. Production hosting must supply connection
deadlines and perimeter controls; a request context does not bound a blocked
socket read. The actual HTTPS test server uses read-header/read/write/idle
timeouts of 5/5/25/60 seconds and a 64 KiB header limit.

Access JSON contains `accessToken`, `tokenType:"Bearer"`, canonical `actorId`,
`principalKind`, `provider:"azure"`, `sourceProfile` and integral Unix
`expiresAt`. Human results add `browserSessionId`, the public own-family UUID.
It is context metadata, not a credential. Machine results omit it. Token bytes
are bounded to 16 KiB and the complete response to 24 KiB. Provider tokens,
refresh handles, facts, roles, signing keys and database details are excluded.
Responses use no-store, no-cache, nosniff and no-referrer headers. Finite error
codes contain no provider error text, code, cookie or token.

## Cookies, context and commit failures

`__Host-ops-v2-recipient` contains 32 random bytes in canonical base64url. The
broker receives the SHA-256 of those decoded bytes. `__Host-ops-v2-renewal`
contains the opaque authenticated renewal handle, at most 3500 bytes. Both use
Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain. Cookies are not Core access
credentials. Duplicate broker cookies, malformed values and Cookie headers over
16 KiB reject before the provider/store. Successful start may extend the same
recipient cookie up to seven days; complete/renew align both cookies to the
stored family's original absolute cutoff. Rotation never slides that cutoff.
Malformed existing broker cookies require explicit browser cookie clearing;
renewal does not repair them.

Existing-context renewal and logout compare the MAC-verified handle's actor
and family with the expected public pair before SQL or a provider grant. A
replacement family of the same actor is a different context too. A mismatch
returns 409 without SQL, provider work or Set-Cookie. Every error leaves cookies
unchanged; only known successful logout clears them. No credentials are
published after failed/unknown commit or a final expiry gate. Session metadata
also rejects the final fractional second after the handle's integral expiry.
An ambiguous response does not roll back a provider grant or committed SQL
change, and the client must not replay the predecessor handle.

## Browser helper

`frontend/src/v2/auth/client.ts` provides `BrowserAuthClient`. Instantiate one
per document. `providers` and explicit `startLogin` choose a configured profile;
`completeCallback` immediately scrubs the query/fragment, then redeems one
matching code flow. `restore` initializes a fresh document; an existing active
marker uses bound renewal. `needAccess` and `withAccess` require an exact public
actor/family pair. `logout` takes the same pair. The helper imports no V1 user
model, DID-prefix inference, AuthContext or directory API. It keeps the short
access result in memory only; application code must not persist or log it.

Supported browsers need HTTPS, Web Locks and working same-origin localStorage.
The exclusive `ops-v2.identity` lock covers all authentication requests and every
cached-token context check. Even a valid memory token must match a fresh shared
marker under that lock. Singleflight combines same-context work within a tab;
each subscriber rechecks the marker before receiving credentials. No
BroadcastChannel delivery is needed for authorization. An admitted operation
captures A's token once and can finish after another tab switches; it never
retries under B or promises instantaneous cancellation.

The only persistent helper value is `ops-v2.browser-context`, at most 512 bytes:
version, active/require-login phase, actor/family pair and SHA-256 of the current
public OAuth state. There are no tokens, facts, permissions or leases in it.
This cooperative same-origin marker selects a browser context; it does not
authorize Core requests or protect against XSS.

Before complete, renew or logout reaches the network, the helper persists
require-login and consumes the pending flow. Only a known successful response
under the still-held lock may publish active state. A failed/unknown request,
abandoned tab or failed logout stays denied across reload; an older callback
cannot recover it. Only a new explicit start and matching completion can do so.
Starting a newer flow supersedes the older flow; a successful same-pair renewal
may preserve that current flow. Provider error metadata is ignored, never
displayed or followed. Only bounded query `response_type=code` callbacks are
supported; duplicates, unknown keys and fragment credentials reject after URL
scrubbing.

Explicit `startLogin` may also replace malformed local metadata with denied
state under the same lock. Ordinary operations never do that or automatically
start login as a fallback. If that repair's fresh start fails, it leaves denied
state; only a known fresh-start response and matching completion can activate a
new context. Starting login from an already valid active marker preserves its
existing actor/family and phase while selecting a new pending flow.

Storage is probed before network work. Each final active write is the last
persistence operation before local publication, after checking the owned
in-flight marker. A synchronous failed write leaves the pre-request denied
state and releases no bearer. This document also latches failures until a new
explicit login. Web Storage is not a SQL transaction or a durable session
authority: storage becoming unavailable after an already successful write
cannot retroactively roll it back across tabs/reloads. Every subsequent
operation must still pass the storage/lock/marker checks. Clearing all site data
discards the context marker as well as cookies; manually deleting only the
marker is not a logout operation.

## Azure registration and qualification

Register the frontend callback as a confidential **Web** redirect, despite its
SPA landing page. The server redeems the code using `client_secret_post` without
a browser Origin; the browser never holds that secret or calls the token
endpoint. An Entra `spa` redirect is a different redemption contract.
[Microsoft's authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
describes this distinction. Set the resource/API application's Microsoft Graph
manifest `api.requestedAccessTokenVersion` to 2. A v2 authorization endpoint
alone does not select the access-token format.
[Microsoft's access-token guidance](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
and [the API application schema](https://learn.microsoft.com/en-us/graph/api/resources/apiapplication?view=graph-rest-1.0)
describe that resource setting. Machine callers must obtain fresh own-API
evidence; re-exchanging a cached hour-old token cannot extend its source age.

Run the scoped actual-browser qualification with installed frontend dependencies,
the pinned Playwright dependency, Node 24, Chrome and Docker available:

```sh
OPS_BROWSER_INTEGRATION=1 go test -race ./internal/operational/identitysql \
  -run '^TestActualAzureTwoTabBrowser$' -count=1 -timeout=150s
```

It bundles the actual helper, opens two owned browser pages with real Web Locks,
and reaches the concrete adapter, signed RSA/JWKS provider, Core verifier and
temporary PostgreSQL. The fixture maps Microsoft endpoints to its owned TLS
server. Ignoring the fixture's self-signed browser certificate does not relax
production TLS. Browser time is aligned to the signed fixture clock. This
proves the local protocol, not a real Entra tenant's registration, directory
replication, account lifecycle or supported-provider configuration. Real tenant
qualification, product pages/router/own-context UX, Privado, enterprise OAuth,
production server mounting and full release composition remain separate work.
