#!/usr/bin/env node
// Qualified local component fixture only. This is NOT evidence that a live
// Indexer supplied this price, or that a real viewer was authorized for it.
// The real exported components and original CSS receive explicit props; no
// production API, token, session injection or network interception is used.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtemp, mkdir, readFile, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const frontend = path.join(path.resolve(process.argv[2] ?? ''), 'frontend');
const output = path.resolve(process.argv[3] ?? '');
assert.ok(process.argv[2] && process.argv[3], 'Usage: component-price-layout.mjs <explorer-source> <private-output-directory>');
const source = name => path.join(frontend, 'src', name);
assert.match(await readFile(source('pages/TokensNative.tsx'), 'utf8'), /export function NativePortfolioRow/);
assert.ok((await readFile(source('components/ExplorerChrome.tsx'), 'utf8')).includes('<main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 py-4 sm:py-8 w-full">'), 'Fixture retains the exact original main-frame constraints');
const require = createRequire(path.join(frontend, 'package.json'));
const { createServer } = await import(pathToFileURL(path.join(frontend, 'node_modules/vite/dist/node/index.js')));
const react = (await import(pathToFileURL(require.resolve('@vitejs/plugin-react')))).default;
const tailwind = require('tailwindcss'), loadConfig = require('tailwindcss/loadConfig'), autoprefixer = require('autoprefixer');
const config = loadConfig(path.join(frontend, 'tailwind.config.js'));
const browserRequire = createRequire(path.join(root, 'e2e/playwright/package.json'));
const { chromium } = browserRequire('@playwright/test');
const temporary = await mkdtemp(path.join(tmpdir(), 'ops-price-component-'));
const hash = value => createHash('sha256').update(value).digest('hex');
const files = ['src/components/TokenPresentation.tsx', 'src/pages/TokensNative.tsx', 'src/components/ExplorerReadPresentation.tsx', 'src/components/ExplorerChrome.tsx', 'src/index.css', 'tailwind.config.js'];
const sourceHashes = Object.fromEntries(await Promise.all(files.map(async file => [file, hash(await readFile(path.join(frontend, file)))])));
let server, browser;
try {
  await mkdir(output, { recursive: true, mode: 0o700 });
  await symlink(path.join(frontend, 'node_modules'), path.join(temporary, 'node_modules'), 'dir');
  await writeFile(path.join(temporary, 'index.html'), '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/fixture.tsx"></script></body></html>');
  const price = '9'.repeat(128), address = '0x' + 'a'.repeat(40);
  const token = { address, symbol: 'FIX', name: 'Qualified price fixture', tokenType: 'ERC20', decimals: 6, usdPrice: price, offChainUpdatedAt: '2026-11-20T00:00:00Z', blockNumber: '1', createdAt: 'fixture' };
  const balance = { address: '0x' + 'b'.repeat(40), tokenAddress: address, balance: '1000000', blockNumber: '1' };
  // main classes are the original ExplorerChrome main frame. The table uses
  // its actual bounded horizontal scroller, rather than hiding page overflow.
  await writeFile(path.join(temporary, 'fixture.tsx'), `
import React from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { TokenHero } from ${JSON.stringify(source('components/TokenPresentation.tsx'))};
import { NativePortfolioRow } from ${JSON.stringify(source('pages/TokensNative.tsx'))};
import { ExplorerTable } from ${JSON.stringify(source('components/ExplorerReadPresentation.tsx'))};
import ${JSON.stringify(source('index.css'))};
const token=${JSON.stringify(token)},balance=${JSON.stringify(balance)};
createRoot(document.getElementById('root')!).render(<MemoryRouter><main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 py-4 sm:py-8 w-full"><div className="space-y-6"><p>Qualified local component fixture; no live price or authorization claim.</p><TokenHero token={token}/><div className="card"><ExplorerTable headings={['Asset','Balance','Price','Value at returned price','Observed block']}><NativePortfolioRow token={token} balance={balance}/></ExplorerTable></div></div></main></MemoryRouter>);
`);
  server = await createServer({ configFile: false, root: temporary, cacheDir: path.join(temporary, '.vite-cache'), plugins: [react()], resolve: { alias: { '@': source('') } }, server: { host: '127.0.0.1', port: 0, fs: { allow: [temporary, frontend] } }, css: { postcss: { plugins: [tailwind({ ...config, content: [path.join(frontend, 'src/**/*.{js,ts,jsx,tsx}'), path.join(temporary, 'fixture.tsx')] }), autoprefixer()] } } });
  await server.listen();
  const origin = 'http://127.0.0.1:' + server.httpServer.address().port;
  browser = await chromium.launch({ channel: process.env.OPS_TEST_BROWSER_CHANNEL ?? 'chrome', headless: true, args: ['--no-proxy-server'] });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } }), errors = [], apiRequests = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { const url = new URL(request.url()); if (url.origin !== origin || url.pathname.startsWith('/api/')) apiRequests.push(url.origin + url.pathname); });
  await page.goto(origin);
  await page.getByRole('heading', { name: token.name, exact: true }).waitFor();
  await page.getByText('$' + price, { exact: true }).waitFor();
  const row = page.getByTestId('portfolio-row');
  await row.getByText(price + ' USD', { exact: true }).waitFor();
  assert.equal((await row.locator('td').nth(3).textContent()).trim(), BigInt(price).toLocaleString('en-US') + ' USD');
  await row.getByText('Indexed token price · ' + token.offChainUpdatedAt, { exact: true }).waitFor();
  const layout = await page.evaluate(() => {
    const main = document.querySelector('main'), price = [...document.querySelectorAll('h1')][0].parentElement.querySelector('span:last-child');
    const row = document.querySelector('[data-testid=portfolio-row]'), priceCell = row.children[2], valueCell = row.children[3], priceText = priceCell.querySelector('span'), valueText = valueCell.querySelector('span') ?? valueCell;
    const dimensions = element => ({ width: element.getBoundingClientRect().width, height: element.getBoundingClientRect().height, lineHeight: getComputedStyle(element).lineHeight });
    return { width: innerWidth, pageWidth: document.documentElement.scrollWidth, mainWidth: main.getBoundingClientRect().width, heroPriceWrap: getComputedStyle(price).overflowWrap, heroPriceBreak: getComputedStyle(price).wordBreak, portfolioRow: dimensions(row), priceCell: dimensions(priceCell), priceText: dimensions(priceText), valueCell: dimensions(valueCell), valueText: dimensions(valueText), horizontalScrollers: [...document.querySelectorAll('.overflow-x-auto')].map(element => ({ width: element.clientWidth, contentWidth: element.scrollWidth })) };
  });
  assert.equal(layout.width, 390); assert.ok(layout.pageWidth <= 390, 'Actual mobile page must not overflow'); assert.ok(layout.mainWidth <= 390);
  assert.equal(layout.heroPriceBreak, 'break-all'); assert.ok(layout.priceText.width >= 128 && layout.priceText.width <= 256, 'Long valid prices retain a readable bounded column'); assert.ok(layout.valueText.width >= 128 && layout.valueText.width <= 256); assert.ok(layout.portfolioRow.height <= 300, 'One long indexed price cannot create a huge row'); assert.ok(layout.horizontalScrollers.every(element => element.width <= 358), 'Table scrolling stays inside original padded frame');
  assert.deepEqual(errors, []); assert.deepEqual(apiRequests, [], 'Pure component props never initiate API or external requests');
  await page.screenshot({ path: path.join(output, 'qualified-price-390.png'), fullPage: true, animations: 'disabled' });
  await page.locator('.overflow-x-auto').first().evaluate(element => { element.scrollLeft = element.scrollWidth; });
  await page.screenshot({ path: path.join(output, 'qualified-price-390-scrolled.png'), fullPage: true, animations: 'disabled' });
  for (const [file, expected] of Object.entries(sourceHashes)) assert.equal(hash(await readFile(path.join(frontend, file))), expected, 'Source stayed fixed during component run');
  await writeFile(path.join(output, 'qualified-price-layout.json'), JSON.stringify({ qualification: 'Explicit local component props with actual source/CSS; no live producer, viewer authority or production price claim', frontend, sourceHashes, sourceManifestSha256: hash(JSON.stringify(sourceHashes)), priceCharacters: price.length, layout, apiRequests, errors, passed: true }, null, 2) + '\n', { mode: 0o600 });
  console.log('PASS qualified local TokenHero/NativePortfolioRow128-character price at390px; zero API/external requests');
} finally {
  await browser?.close(); await server?.close(); await rm(temporary, { recursive: true, force: true });
}
