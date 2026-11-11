# V2 central sign in

The V2 browser entry uses the selected Azure and Privado broker profiles. It
does not mount the legacy React authentication provider or store access or
refresh tokens in browser storage. The existing `MultiBrowserAuthClient` owns
Web Locks, the noncredential shared context marker and actual broker renewal.

Build with Node 24.22.1 and `cd frontend && npm run build:v2`. This produces
`frontend/dist-v2/index-v2.html` and its `assets-v2` JavaScript/CSS. The dedicated
build excludes the legacy public directory and external fonts.

The server owner creates `identityweb.New` with the selected broker-multi
snapshot and `os.DirFS` for that built directory, then registers it on the same
owned HTTPS mux as `identityhttp.NewMulti`, `ssohttp.New` and `selfhttp.New`.
The selected snapshot supplies the exact host and completion path. The browser
handler serves `/login`, `/auth/sso`, `/auth/azure/callback`, the selected
completion path and the bounded selected assets. It does not provide an
arbitrary SPA fallback. Startup copies the build into bounded immutable memory;
unknown files, symlinks, source maps and oversized files fail startup.

The owner supplies TLS and bounded server header/idle timeouts. These handlers
also require real read/write deadlines through `http.ResponseController`;
wrappers must expose `Unwrap`. Responses use no-store, no-referrer, nosniff and
a CSP that allows only owned scripts, styles and same-origin API connections.
HTTPS, Web Locks, local storage and modern AbortSignal support are required.

Azure callback query parameters are removed synchronously before rendering or
asynchronous startup. Privado presents a QR/mobile link using
`iden3comm://?request_uri=...` and a web-wallet universal link using the existing
public UUID request endpoint. The original OPS tab polls while visible, shows
the full holder DID/network/profile and requires an explicit identity choice.
That choice authenticates the user; it is not disclosure consent. A new
Privado session document genuinely re-proves rather than rebuilding a JWT
from a renewal cookie. Hosted wallet and Azure tenant deployment still require
their own environment qualification.

Each document owns a selected Actor/session/profile, operation IDs and a fixed
SSO flow expiry. Changed account context cancels private work, clears display
facts and requires explicit **Use current session** or a fresh login. Delayed
self, proof, renewal and completion responses cannot publish under a newer
owner, including their cleanup. Page suspension clears private display and
selection synchronously. A persisted back/forward return reloads the document
and genuinely verifies again; it does not revive a stopped controller.
An interrupted SSO completion is not retried. Session storage contains
only the recipient-bound flow UUID, original expiry and noncredential phase;
a Ready or lost flow must be restarted by the application.

`GET /api/v2/self` independently verifies one original Bearer JWT through the
selected Core snapshot and runtime View. It accepts verified human and service
principals, and returns their Actor, kind, original expiry, source profile and
digest plus their own sorted organization IDs/names/slugs and organization
admin display flags. It has no subject selector, cookie authentication, group
directory, user rows or provider call. Every later operation must authorize
independently; these flags authorize nothing. Self display is refreshed after
actual access renewal and cleared at original expiry.

The self handler supports at most 256 organizations. Standard JSON's
conservative maximum, charging all 128 profile-ID bytes and all organization
name bytes at six escaped bytes each, is 448,505 bytes including newline. Its
response cap is 512 KiB; no organizations or valid names are truncated. The
pure self package has a permanent dependency check excluding broker, SQL,
legacy RBAC and EVM execution dependencies.
