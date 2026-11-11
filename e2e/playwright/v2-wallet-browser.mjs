import assert from 'node:assert/strict'
import { chromium } from '@playwright/test'
import { privateKeyToAccount } from '../../frontend/node_modules/viem/_esm/accounts/index.js'
import { hexToString } from '../../frontend/node_modules/viem/_esm/utils/encoding/fromHex.js'

const [ops, app, instant] = process.argv.slice(2)
assert.match(ops ?? '', /^https:\/\/ops\.test:[0-9]+$/)
assert.match(app ?? '', /^https:\/\/app\.test:[0-9]+$/)
const accounts = ['17', '18', '19', '20'].map(byte => privateKeyToAccount('0x' + byte.repeat(32)))
const addresses = accounts.map(account => account.address.toLowerCase())
const browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--host-resolver-rules=MAP ops.test 127.0.0.1,MAP app.test 127.0.0.1', '--no-proxy-server'] })
const context = await browser.newContext({ ignoreHTTPSErrors: true }) // Owned fixture TLS only.
let subject = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', held = null, waiting = null, stage = 'startup'
let verifications = 0, cases = 0
const note = label => { cases++; process.stdout.write(`PASS ${label}\n`) }
context.on('request', request => { if (new URL(request.url()).pathname.endsWith('/eth/link/verify')) verifications++ })
await context.exposeBinding('__ownedWalletRequest', async (_binding, args) => {
  if (args.method === 'eth_accounts' || args.method === 'eth_requestAccounts') return addresses
  assert.equal(args.method, 'personal_sign')
  assert.ok(Array.isArray(args.params) && args.params.length === 2)
  const signer = accounts.find(account => account.address.toLowerCase() === args.params[1])
  assert.ok(signer); assert.match(args.params[0], /^0x[0-9a-f]+$/)
  const message = hexToString(args.params[0])
  assert.ok(message.startsWith('OPS wallet link v1\nService: https://ops.test\nNetwork: sha256:'))
  assert.ok(message.endsWith('This does not authorize a transaction.'))
  if (held) { const release = held; held = null; waiting = release; await release.promise; waiting = null }
  return signer.signMessage({ message: { raw: args.params[0] } })
})
await context.addInitScript(() => {
  const listeners = new Map()
  window.ethereum = {
    request: args => window.__ownedWalletRequest(args),
    on: (name, callback) => { if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name).add(callback) },
    removeListener: (name, callback) => listeners.get(name)?.delete(callback),
  }
})
const localOPS = ops.replace('ops.test', '127.0.0.1')
await context.route('https://login.microsoftonline.com/**', async route => {
  const authorization = new URL(route.request().url())
  const response = await context.request.post(localOPS + '/__test/wallet-identity', { headers: { Host: new URL(ops).host, Origin: ops }, data: { AuthorizationURL: authorization.href, Subject: subject } })
  assert.equal(response.status(), 204)
  const callback = new URL(ops + '/auth/azure/callback')
  callback.searchParams.set('state', authorization.searchParams.get('state')); callback.searchParams.set('code', 'owned-wallet-browser-code')
  await route.fulfill({ status: 302, headers: { Location: callback.href }, body: '' })
})
const page = await context.newPage()
await page.clock.install({ time: Date.parse(instant) })
const panel = p => p.getByRole('region', { name: 'Your wallet links' })
const choose = async (p, address) => {
  await panel(p).getByRole('button', { name: 'Link wallet', exact: true }).click()
  await panel(p).getByRole('button', { name: address, exact: true }).click()
  await panel(p).getByRole('button', { name: 'Sign ownership proof', exact: true }).click()
}
const hold = () => {
  let resolve
  const promise = new Promise(r => { resolve = r })
  held = { promise, resolve }; return held
}
const waitHeld = async () => { for (let i = 0; i < 100 && !waiting; i++) await page.waitForTimeout(25); assert.ok(waiting) }
try {
  process.stdout.write(`Owned actual built wallet paths / Chrome ${browser.version()}; controlled EIP1193 and real EIP191, not a physical extension deployment\n`)
  stage = 'app-login'; await page.goto(app)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await page.getByRole('button', { name: /Sign in with Azure/ }).click()
  await page.getByRole('button', { name: 'Continue to application', exact: true }).click(); await page.waitForURL(app + '/')
  const actorA = await page.locator('[data-field=app-actor]').textContent()
  stage = 'app-link'; await page.goto(app + '/wallets'); await panel(page).waitFor()
  await choose(page, addresses[0]); await panel(page).getByRole('button', { name: 'Confirm link', exact: true }).click()
  await panel(page).getByRole('button', { name: 'Unlink', exact: true }).waitFor()
  note('Explorer four-route BFF links actual signed ownership and loads real SQL proof2')
  stage = 'central-own'; const central = await context.newPage(); await central.clock.install({ time: Date.parse(instant) }); await central.goto(ops + '/login')
  await central.locator('[data-field=actorId]').waitFor(); assert.equal(await central.locator('[data-field=actorId]').textContent(), actorA)
  await panel(central).getByRole('button', { name: 'Refresh links', exact: true }).click()
  await panel(central).getByText(addresses[0], { exact: true }).waitFor()
  stage = 'central-link'; await choose(central, addresses[1]); await panel(central).getByRole('button', { name: 'Confirm link', exact: true }).click()
  await panel(central).getByText(addresses[1], { exact: true }).waitFor()
  note('central own panel uses original Core bearer and the same actual Actor-global wallet store')
  stage = 'central-same-pair-held'; const centralHold = hold(); await choose(central, addresses[2]); await waitHeld()
  const beforeCentral = verifications
  const renewal = await context.newPage(); await renewal.clock.install({ time: Date.parse(instant) }); await renewal.goto(ops + '/login')
  await renewal.locator('[data-field=actorId]').waitFor()
  await central.waitForFunction(() => !document.querySelector('[aria-label="Your wallet links"] pre'))
  centralHold.resolve(); await central.waitForTimeout(100)
  assert.equal(await panel(central).getByRole('button', { name: 'Confirm link', exact: true }).count(), 0)
  assert.equal(await central.locator('[data-field=actorId]').textContent(), actorA); assert.equal(verifications, beforeCentral)
  note('actual native same-pair renewal events clear central held proof without changing the selected identity')
  stage = 'app-unlink'; await page.bringToFront(); await panel(page).getByRole('button', { name: 'Refresh links', exact: true }).click()
  await panel(page).getByText(addresses[1], { exact: true }).waitFor()
  await panel(page).getByRole('listitem').filter({ hasText: addresses[0] }).getByRole('button', { name: 'Unlink', exact: true }).click()
  await panel(page).getByRole('button', { name: 'Confirm permanent unlink', exact: true }).click()
  // While DELETE/refresh is in flight the address appears in both its row and
  // the confirmation warning. The oracle concerns removal of the actual row.
  await panel(page).getByRole('listitem').filter({ hasText: addresses[0] }).waitFor({ state: 'detached' })
  await panel(page).getByRole('button', { name: 'Link wallet', exact: true }).click(); await panel(page).getByRole('button', { name: addresses[0], exact: true }).click()
  await panel(page).getByRole('alert').filter({ hasText: 'Wallet state conflict' }).waitFor()
  assert.equal(await page.locator('[data-field=app-actor]').textContent(), actorA)
  note('terminal native revocation survives refresh; business409 does not clear app authentication')
  stage = 'app-held-account-switch'; const appHold = hold(); await choose(page, addresses[3]); await waitHeld(); const beforeSwitch = verifications
  subject = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  await renewal.getByRole('button', { name: /Sign in with Azure/ }).click(); await renewal.locator('[data-field=actorId]').waitFor()
  await renewal.goto(app); await renewal.getByRole('button', { name: 'Switch account', exact: true }).click(); await renewal.getByRole('button', { name: 'Continue to application', exact: true }).click(); await renewal.waitForURL(app + '/')
  assert.notEqual(await renewal.locator('[data-field=app-actor]').textContent(), actorA)
  await page.getByRole('button', { name: 'Use the current app session', exact: true }).waitFor()
  assert.equal(await page.locator('[data-field=app-actor]').count(), 0)
  appHold.resolve(); await page.waitForTimeout(100); assert.equal(verifications, beforeSwitch)
  assert.equal(await page.getByRole('button', { name: 'Confirm link', exact: true }).count(), 0)
  note('actual app activation change clears private proof and late wallet result never verifies under the new account')
  assert.equal(verifications, 2)
  process.stdout.write(`PASS owned wallet cases=${cases}; exactly two successful verify requests; SQL assertions follow in Go\n`)
} catch (error) {
  const category = error?.message?.includes('strict mode violation') ? 'locator_strict' : error?.name ?? 'failure'
  process.stderr.write(`Owned wallet browser FAILED stage=${stage}; category=${category}\n`)
  process.exitCode = 1
} finally {
  held?.resolve(); waiting?.resolve(); await browser.close()
}
