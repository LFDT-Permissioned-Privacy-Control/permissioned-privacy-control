# Local V2 demo wallet

This separate tool supplies four **public test identities** for the runnable
native V2 demo. It reuses the pinned SDK and actual AuthV2/SigV2 circuits from
`tools/v2-test-wallet`. It does not belong in the production image or Core.

Admin, deployer and reader have distinct credentials with role values 1, 2 and
3. Outsider has an identity without a role credential. Generated bundle mappings
determine permissions; the picker does not grant them. Each request passes
through the production Privado verifier, native broker and Core verifier.
The picker never completes a login, creates a family or issues an OPS token.

The identity-state endpoint is an explicit local fixture backed by the SDK's
actual sparse tree and issuer state. Its `polygon:mumbai` identifier names that
fixture namespace. It does not claim a live Mumbai deployment or a hosted
Privado issuer. The application's real Reth node, indexer and creation observer
are separate services.

Prepare the shared prerequisites from the repository root:

```sh
npm ci --prefix tools/v2-test-wallet --ignore-scripts --no-audit --no-fund
node scripts/v2-test-prerequisites.mjs
```

Run with Node 24 using an explicit composition-generated config:

```sh
NODE_EXTRA_CA_CERTS=/runtime/demo-ca.crt \
  node tools/v2-demo-wallet/server.mjs --config /runtime/demo-wallet.json
```

Example config inside the demo network:

```json
{
  "listenHost": "0.0.0.0",
  "listenPort": 9444,
  "origin": "https://localhost:9444",
  "opsOrigin": "https://localhost:8443",
  "opsUpstream": "https://ops:8443",
  "stateRpcUrl": "https://demo-wallet:9444/rpc",
  "tlsCertificateFile": "/runtime/wallet.crt",
  "tlsPrivateKeyFile": "/runtime/wallet.key",
  "outputDirectory": "/runtime/wallet-state"
}
```

Publish the demo's ports on loopback. Trust the owned demo CA only in the demo
processes; do not install it in the host trust store or disable TLS validation.
The certificate needs the configured public and internal hostnames. The OPS
Linux container uses the same owned CA through `SSL_CERT_FILE`.

On startup the tool writes `metadata.json`, exact `role-context.json` bytes and
`identity-state.json`. Bootstrap pins the context digest and compiles the
advertised issuer, verifier, profiles and mappings into the approved bundles.
Identities reconstruct from fixed public test seeds; mutable GIST controls are
disabled in demo mode. Normal restart checks the persisted identity/state
fingerprint and refuses a changed baseline. Preserve this directory across
ordinary restarts. An explicit full demo reset can recreate the baseline and its
operational stores together.

To sign in or switch identities:

1. In OPS, select **Sign in with Privado · demo-reader** (or another demo profile).
2. Expand **Verification request** and copy the displayed URI.
3. Open the demo wallet, select the same identity, paste the URI and select
   **Generate and submit proof**.
4. Return to the original OPS tab and select **Use this identity** after OPS
   displays the verified holder DID.
5. For another identity, select **Sign out of OPS** and repeat with its profile.

A refresh that needs a new Privado proof uses the same steps and preserves the
existing session only after native verification. Outsider authenticates with no
organization membership and may correctly receive 403 from protected data APIs.
Wallet linking still needs its separate EOA ownership challenge and signature;
this picker does not pretend to be an injected Ethereum wallet.

The sidecar accepts only the configured OPS origin's exact public request path,
checks the original callback, verifier and selected role predicate, rejects
redirects, and submits a fresh proof without browser cookies or authorization
headers. One proof job runs at a time. Its state adapter permits only bounded,
read-only requests to the selected demo state contract.

Run its focused boundary controls with:

```sh
node --test tools/v2-demo-wallet/boundary.test.mjs
```

For an operational wallet-link check, save the production endpoint's exact
`message` string without adding a newline, then sign it with the matching public
demo account:

```sh
node tools/v2-demo-wallet/sign-message.mjs \
  --persona reader --message-file /runtime/original-challenge.txt \
  --service-origin https://localhost:8443
```

The result contains only `persona`, `address` and the EIP191 `signature`. Submit
it with the original nonce to the normal wallet-link verification endpoint. The
CLI checks the service origin, selected address, nonce format and original
five-minute expiry before signing. It does not call a privileged database or
mint an identity token.

`evm-wallets.json` contains the four public addresses. Their **public demo private
keys** are the 32-byte integers 1, 2, 3 and 4 for admin, deployer, reader and
outsider. Never transfer real funds to these addresses. For the browser wallet
panel, import the matching public demo key into an isolated MetaMask test
profile; the normal injected-wallet connect/sign/confirm flow then applies.
Only the local demo chain should fund these accounts.

The demo keeps the existing `eth_sendTransaction` permission classification for
**signed raw submission**. That capability is required even though the wire
method is `eth_sendRawTransaction`; a raw-method grant alone is insufficient.
The runtime independently sets `nodeSigning: false`, so unsigned
`eth_sendTransaction` requests remain unavailable. The walkthrough checks that
separation before submitting its genuinely signed application transaction.
