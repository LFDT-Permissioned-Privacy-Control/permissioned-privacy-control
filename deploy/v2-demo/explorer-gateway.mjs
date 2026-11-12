// Local demo TLS ingress. The production BFF still validates exact Host,
// Origin, cookies and CSRF. No identity headers or tokens are synthesized.
import { createServer } from 'node:https';
import { request } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
const port = Number(process.env.OPS_V2_DEMO_EXPLORER_PORT);
const api = Number(process.env.OPS_V2_DEMO_EXPLORER_API_PORT);
if (!Number.isInteger(port) || !Number.isInteger(api) || port <= 0 || api <= 0) throw Error('Invalid demo ports');
const types = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' };
const server = createServer({ cert: await readFile('/demo/tls.crt'), key: await readFile('/demo/tls.key') }, async (req, res) => {
  if (req.headers.host !== `localhost:${port}`) { res.writeHead(421); res.end(); return; }
  const url = new URL(req.url, `https://localhost:${port}`);
  if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
    const upstream = request({ hostname: '127.0.0.1', port: api, method: req.method, path: req.url, headers: req.headers, timeout: 20_000 }, response => {
      res.writeHead(response.statusCode ?? 502, response.headers); response.pipe(res);
    });
    upstream.on('timeout', () => upstream.destroy());
    upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.on('aborted', () => upstream.destroy()); res.on('close', () => upstream.destroy());
    req.pipe(upstream); return;
  }
  if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405); res.end(); return; }
  try {
    let body, type;
    if (url.pathname === '/config.js') {
      body = 'window.__runtimeConfig={VITE_AUTH_PROTOCOL:"ops-v2",VITE_API_URL:"/api"};\n'; type = 'text/javascript';
    } else {
      const asset = /^\/assets\/[A-Za-z0-9_.-]+$/.test(url.pathname);
      if (url.pathname.startsWith('/assets/') && !asset) { res.writeHead(404); res.end(); return; }
      const file = asset ? '/app/web' + url.pathname : '/app/web/index-v2.html';
      body = await readFile(file); type = types[path.extname(file)] ?? 'application/octet-stream';
    }
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch { res.writeHead(404); res.end(); }
});
server.requestTimeout = 25_000; server.headersTimeout = 5000;
server.listen(port, '127.0.0.1');
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { server.closeAllConnections(); server.close(); });
