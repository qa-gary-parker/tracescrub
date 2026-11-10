// Opens a (scrubbed) trace in Playwright's own trace viewer, headlessly, and
// checks that it loads and lists the recorded actions.
//
//   npm run build && npm run verify:viewer [-- path/to/trace.zip]
//
// Without an argument it scrubs test/fixtures/trace.zip into a temp dir first.
// The viewer is the static build that ships with playwright-core.
import { chromium } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { createReadStream, existsSync, mkdtempSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const require = createRequire(import.meta.url);
const viewerDir = path.join(path.dirname(require.resolve('playwright-core/package.json')), 'lib', 'vite', 'traceViewer');
if (!existsSync(path.join(viewerDir, 'index.html'))) throw new Error(`trace viewer not found at ${viewerDir}`);

let tracePath = process.argv[2];
if (!tracePath) {
  const out = mkdtempSync(path.join(os.tmpdir(), 'tracescrub-viewer-'));
  execFileSync(process.execPath, [path.join(root, 'dist', 'cli.js'), 'scrub', path.join(root, 'test', 'fixtures', 'trace.zip'), '--out', out], {
    stdio: 'inherit',
  });
  tracePath = path.join(out, 'trace.zip');
}

const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ttf': 'font/ttf', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };
const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  let file;
  if (url.pathname === '/trace.zip') file = path.resolve(tracePath);
  else if (url.pathname.startsWith('/viewer/')) file = path.join(viewerDir, decodeURIComponent(url.pathname.slice('/viewer/'.length)) || 'index.html');
  if (!file || !file.startsWith(viewerDir) && file !== path.resolve(tracePath) || !existsSync(file) || !statSync(file).isFile()) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { 'Content-Type': types[path.extname(file)] ?? 'application/octet-stream' });
  createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch();
let ok = false;
try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(`${origin}/viewer/index.html?trace=${encodeURIComponent(`${origin}/trace.zip`)}`);
  const fill = page.getByText(/^Fill/).first();
  await fill.waitFor({ timeout: 20000 });
  const actions = await page.locator('.action-title, .tree-item-title').allInnerTexts().catch(() => []);
  const body = await page.locator('body').innerText();
  if (/could not load/i.test(body)) throw new Error('viewer reported that the trace could not be loaded');
  console.log(`trace viewer loaded ${tracePath}`);
  console.log(`actions: ${actions.slice(0, 12).map((a) => a.replace(/\s+/g, ' ').trim()).filter(Boolean).join(' | ')}`);
  if (errors.length) console.log(`page errors: ${errors.join('; ')}`);
  ok = true;
} finally {
  await browser.close();
  server.close();
}
process.exitCode = ok ? 0 : 1;
