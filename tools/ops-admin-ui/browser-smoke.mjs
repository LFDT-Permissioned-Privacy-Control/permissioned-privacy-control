// Optional real-browser functional check. Uses an isolated headless Chrome
// profile and loopback-only static server; no npm dependencies or OPS service.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, writeFile, rm, access } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = path.dirname(fileURLToPath(import.meta.url));
const chrome = process.env.OPS_UI_CHROME_BIN || [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome', '/usr/bin/chromium',
].find(existsSync);
if (!chrome) throw new Error('Set OPS_UI_CHROME_BIN to a local Chrome/Chromium executable.');
const scratch = await mkdtemp(path.join(os.tmpdir(), 'ops-policy-editor-'));
const output = process.argv[2] ? path.resolve(process.argv[2]) : path.join(scratch, 'evidence');
await mkdir(output, { recursive: true });
const downloads = path.join(scratch, 'downloads');
await mkdir(downloads);
const assets = new Map([
  ['/', ['index.html', 'text/html']], ['/index.html', ['index.html', 'text/html']],
  ['/app.mjs', ['app.mjs', 'text/javascript']], ['/model.mjs', ['model.mjs', 'text/javascript']],
  ['/style.css', ['style.css', 'text/css']],
]);
const server = createServer(async (request, response) => {
  const asset = assets.get(request.url);
  if (!asset || request.method !== 'GET') { response.writeHead(404); response.end(); return; }
  response.writeHead(200, { 'Content-Type': asset[1], 'Cache-Control': 'no-store' });
  response.end(await readFile(path.join(root, asset[0])));
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = spawn(chrome, [
  '--headless=new', '--disable-gpu', '--no-sandbox', '--disable-extensions',
  '--disable-background-networking', '--disable-component-update', '--disable-sync',
  '--no-first-run', '--no-default-browser-check', '--remote-debugging-address=127.0.0.1',
  '--remote-debugging-port=0', `--user-data-dir=${path.join(scratch, 'browser')}`,
], { stdio: 'ignore' });
let socket;
const pending = new Map();
let nextID = 0;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(condition, message, timeout = 10000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await condition()) return; await delay(50); }
  throw new Error(message);
}
function send(method, params = {}, sessionId) {
  const id = ++nextID;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}

try {
  const portFile = path.join(scratch, 'browser', 'DevToolsActivePort');
  await until(async () => { try { await access(portFile); return true; } catch { return false; } }, 'Chrome did not expose its isolated debugging port');
  const [port] = (await readFile(portFile, 'utf8')).split('\n');
  const info = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  socket = new WebSocket(info.webSocketDebuggerUrl);
  await once(socket, 'open');
  const pageErrors = [];
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') pageErrors.push(message.params.exceptionDetails.text);
    const call = pending.get(message.id);
    if (!call) return;
    clearTimeout(call.timer); pending.delete(message.id);
    if (message.error) call.reject(new Error(JSON.stringify(message.error))); else call.resolve(message.result);
  });
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  await send('Page.enable', {}, sessionId);
  await send('Runtime.enable', {}, sessionId);
  await send('DOM.enable', {}, sessionId);
  await send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads });
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true, userGesture: true }, sessionId);
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false }, sessionId);
  await send('Page.navigate', { url: origin }, sessionId);
  await until(() => evaluate("document.readyState === 'complete' && !!document.getElementById('open')"), 'Editor did not load');
  const original = Buffer.from('{\r\n  "name": "Банк 🏦 <img src=x onerror=window.__injected=true>"\r\n}\r\n');
  const sourceFile = path.join(scratch, 'groups.json');
  await writeFile(sourceFile, original);
  const { root: document } = await send('DOM.getDocument', {}, sessionId);
  const { nodeId } = await send('DOM.querySelector', { nodeId: document.nodeId, selector: '#open' }, sessionId);
  await send('DOM.setFileInputFiles', { nodeId, files: [sourceFile] }, sessionId);
  await until(() => evaluate("document.getElementById('filename').textContent === 'groups.json'"), 'Imported source not displayed');
  assert.equal(await evaluate('window.__injected === undefined && document.querySelectorAll("img").length === 0'), true);
  await evaluate('document.getElementById("download").click()');
  const downloaded = path.join(downloads, 'groups.json');
  await until(async () => { try { await access(downloaded); return true; } catch { return false; } }, 'Original source download missing');
  assert.deepEqual(await readFile(downloaded), original, 'Browser changed unedited CRLF/Unicode bytes');
  await rm(downloaded);
  const edited = '{"groups":[]}\n';
  await evaluate(`{ const el = document.getElementById('editor'); el.value = ${JSON.stringify(edited)}; el.dispatchEvent(new Event('input', { bubbles: true })); }`);
  assert.match(await evaluate('document.getElementById("status").textContent'), /Edited draft.*not checked/);
  assert.match(await evaluate('document.getElementById("syntax").textContent'), /Run the OPS checker/);
  await evaluate('document.getElementById("download").click()');
  await until(async () => { try { await access(downloaded); return true; } catch { return false; } }, 'Edited source download missing');
  assert.deepEqual(await readFile(downloaded), Buffer.from(edited));
  let image = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, sessionId);
  await writeFile(path.join(output, 'policy-editor-desktop.png'), Buffer.from(image.data, 'base64'));
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, sessionId);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'Mobile page overflow');
  image = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, sessionId);
  await writeFile(path.join(output, 'policy-editor-mobile.png'), Buffer.from(image.data, 'base64'));
  assert.deepEqual(pageErrors, []);
  const report = { passed: true, browser: info.Browser, checks: ['real file import', 'CRLF/Unicode byte-preserving original download', 'edited download', 'source HTML escaped', 'preliminary-only status', 'mobile no overflow', 'no page exceptions'], noOPSOrGitConnection: true };
  await writeFile(path.join(output, 'browser-smoke.json'), JSON.stringify(report, null, 2)+'\n');
  console.log(JSON.stringify(report));
} finally {
  for (const call of pending.values()) clearTimeout(call.timer);
  socket?.close();
  browser.kill('SIGTERM');
  if (browser.exitCode === null) await Promise.race([once(browser, 'exit'), delay(3000)]);
  if (browser.exitCode === null) browser.kill('SIGKILL');
  await new Promise(resolve => server.close(resolve));
  await rm(scratch, { recursive: true, force: true });
}
