import { test, expect, type FrameLocator, type Locator } from '@playwright/test';
import { closeSync, cpSync, createReadStream, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const cli = path.join(root, 'dist', 'cli.js');
const fixtures = path.join(root, 'test', 'fixtures');
const outDir = path.join(import.meta.dirname, 'out');
const viewerDir = path.join(path.dirname(createRequire(import.meta.url).resolve('playwright-core/package.json')), 'lib', 'vite', 'traceViewer');
const TRACE = 'test-results/login-chromium/trace.zip';
const PASSWORD = 'tsk_FAKE_Passw0rd_9f3a7c';
const RED = '#F85149';
const GREEN = '#3FB950';

// The committed fixtures, laid out the way a CI job leaves them
function workspace() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'tracescrub-demo-'));
  mkdirSync(path.join(dir, path.dirname(TRACE)), { recursive: true });
  cpSync(path.join(fixtures, 'trace.zip'), path.join(dir, TRACE));
  cpSync(path.join(fixtures, 'login.har'), path.join(dir, 'test-results', 'login.har'));
  cpSync(path.join(fixtures, 'storageState.json'), path.join(dir, 'test-results', 'storageState.json'));
  cpSync(path.join(fixtures, 'report'), path.join(dir, 'playwright-report'), { recursive: true });
  return dir;
}

// One fd for stdout and stderr keeps the lines in the order a terminal shows them
function tracescrub(cwd: string, args: string[]) {
  const log = path.join(cwd, '.out.log');
  const fd = openSync(log, 'w');
  spawnSync(process.execPath, [cli, ...args], { cwd, stdio: ['ignore', fd, fd] });
  closeSync(fd);
  return readFileSync(log, 'utf8').trimEnd();
}

const SHELL = '<!doctype html><html><head><meta charset="utf-8"></head><body><iframe id="viewer"></iframe><div id="term"></div><div id="demo-caption"></div></body></html>';
const types: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ttf': 'font/ttf', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };

function serve(work: string, before: Buffer) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === '/') return void res.writeHead(200, { 'Content-Type': 'text/html' }).end(SHELL);
    if (url.pathname === '/before.zip') return void res.writeHead(200, { 'Content-Type': 'application/zip' }).end(before);
    if (url.pathname === '/after.zip') return void res.writeHead(200, { 'Content-Type': 'application/zip' }).end(readFileSync(path.join(work, TRACE)));
    if (url.pathname.startsWith('/viewer/')) {
      const file = path.join(viewerDir, decodeURIComponent(url.pathname.slice('/viewer/'.length)) || 'index.html');
      if (file.startsWith(viewerDir) && existsSync(file) && statSync(file).isFile()) {
        res.writeHead(200, { 'Content-Type': types[path.extname(file)] ?? 'application/octet-stream' });
        return void createReadStream(file).pipe(res);
      }
    }
    res.writeHead(404).end();
  });
  return new Promise<{ origin: string; close: () => void }>(resolve =>
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      resolve({ origin: `http://127.0.0.1:${port}`, close: () => server.close() });
    }));
}

async function mark(target: Locator, color: string) {
  await expect(target).toBeVisible();
  await target.evaluate((el, c) => {
    el.scrollIntoView({ block: 'center' });
    el.style.outline = `3px solid ${c}`;
    el.style.outlineOffset = '2px';
  }, color);
}

test('record the scrub demo', async ({ browser }, testInfo) => {
  const viewport = testInfo.project.use.viewport!;
  const { zoom, caption: captionPx, lines, term: termPx } = testInfo.project.metadata as { zoom: number; caption: number; lines: number; term: number };
  const portrait = viewport.height > viewport.width;

  const work = workspace();
  const before = readFileSync(path.join(work, TRACE));
  const server = await serve(work, before);

  const context = await browser.newContext({ viewport, colorScheme: 'dark', recordVideo: { dir: testInfo.outputDir, size: viewport } });
  const page = await context.newPage();
  const recordingStart = Date.now();
  await page.goto(server.origin + '/');
  await page.evaluate(([w, h, z, px, lines, termPx]) => {
    const bar = px * (1.25 * lines + 1);
    const pad = Math.round(termPx * 1.2);
    document.head.appendChild(document.createElement('style')).textContent =
      `html,body{margin:0;height:100%;overflow:hidden;background:#0B0D0C}`
      + `#viewer{position:fixed;left:0;top:0;border:0;width:${w / z}px;height:${(h - bar) / z}px;transform:scale(${z});transform-origin:0 0;background:#0B0D0C}`
      // The terminal covers the viewer without taking its clicks, so the viewer can load and be driven underneath
      + `#term{position:fixed;left:0;top:0;right:0;z-index:2;pointer-events:none;height:${h - bar}px;box-sizing:border-box;padding:${pad}px;overflow:hidden;background:#0B0D0C;`
      + `color:#9DA5AE;font:${termPx}px/1.4 ui-monospace,Menlo,monospace;white-space:pre-wrap;overflow-wrap:anywhere}`
      + `#term div{min-height:1.4em}#term .cmd{color:#E6E8E3}#term .p{color:#3FB950}#term .file{color:#E6E8E3;font-weight:700}`
      + `#term .bad{color:#F85149;font-weight:700}#term .good{color:#3FB950;font-weight:700}#term .dim{color:#6E7681}`
      + `#term.off{visibility:hidden}`
      + `#demo-caption{position:fixed;left:0;right:0;bottom:0;height:${bar}px;z-index:99999;box-sizing:border-box;`
      + `display:flex;align-items:center;justify-content:center;padding:0 ${px}px;background:#0B0D0C;`
      + `border-top:1px solid #3FB950;color:#E6E8E3;font:600 ${px}px/1.25 ui-monospace,Menlo,monospace;text-align:center;white-space:${lines > 1 ? 'pre-line' : 'normal'}}`;
  }, [viewport.width, viewport.height, zoom, captionPx, lines, termPx]);

  const show = (what: 'viewer' | 'term') => page.evaluate(w => { document.getElementById('term')!.classList.toggle('off', w === 'viewer'); }, what);

  const openTrace = async (zip: string): Promise<FrameLocator> => {
    await page.evaluate(src => { (document.getElementById('viewer') as HTMLIFrameElement).src = src; },
      `/viewer/index.html?trace=${encodeURIComponent(server.origin + zip)}`);
    const v = page.frameLocator('#viewer');
    const fill = v.getByText(/^Fill "/).nth(1);
    await expect(fill).toBeVisible({ timeout: 20_000 });
    await fill.click();
    await v.getByText('Call', { exact: true }).click();
    return v;
  };

  // Commands are typed, then print the real output they gave when they ran
  const type = (cmd: string) => page.evaluate(async cmd => {
    const row = document.getElementById('term')!.lastElementChild!;
    for (const ch of cmd) {
      row.append(ch);
      await new Promise(r => setTimeout(r, 30));
    }
  }, cmd);
  const print = (out: string) => page.evaluate(async out => {
    const term = document.getElementById('term')!;
    const add = (cls: string, text: string) => {
      const row = term.appendChild(document.createElement('div'));
      row.className = cls;
      row.textContent = text;
      term.scrollTop = term.scrollHeight;
      return row;
    };
    await new Promise(r => setTimeout(r, 300));
    for (const line of out.split('\n')) {
      const cls = /^Found \d/.test(line) ? 'bad'
        : /^(No secrets found|Scrubbed \d)/.test(line) ? 'good'
        : /^(Note|Output):/.test(line) ? 'dim'
        : /^\S/.test(line) ? 'file' : '';
      add(cls, line);
      await new Promise(r => setTimeout(r, 8));
    }
    add('cmd', '').innerHTML = '<span class="p">$</span> ';
  }, out);
  const shell = async (cmd: string, out: string) => { await type(cmd); await print(out); };
  const clear = () => page.evaluate(() => { document.getElementById('term')!.innerHTML = '<div class="cmd"><span class="p">$</span> </div>'; });

  let start = 0;
  const cues: string[] = [];
  // A beat sets its caption, runs its action, then holds until its length is up
  const beat = async (text: string, ms: number, spoken: string, action?: () => Promise<unknown>) => {
    const t = Date.now();
    if (!start) start = t;
    cues.push(`${((t - start) / 1000).toFixed(2)}\t${spoken}`);
    await page.evaluate(s => { document.getElementById('demo-caption')!.textContent = s; }, text);
    await action?.();
    const left = ms - (Date.now() - t);
    if (left > 0) await page.waitForTimeout(left);
  };

  // The three commands run in order up front, so captions can carry their numbers
  const targets = './test-results ./playwright-report';
  const checkCmd = `npx tracescrub check ${targets}`;
  const scrubCmd = `npx tracescrub scrub ${targets} --in-place`;
  const checkOut = tracescrub(work, ['check', ...targets.split(' ')]);
  const scrubOut = tracescrub(work, ['scrub', ...targets.split(' '), '--in-place']);
  const recheckOut = tracescrub(work, ['check', ...targets.split(' ')]);
  const found = /^Found (\d+) potential secret\(s\) in (\d+) of (\d+) file/m.exec(checkOut);
  const scrubbed = /^Scrubbed (\d+) secret\(s\) in (\d+) of (\d+) file/m.exec(scrubOut);
  const clean = /^No secrets found in (\d+) file/m.exec(recheckOut);
  expect(found, checkOut).not.toBeNull();
  expect(scrubbed, scrubOut).not.toBeNull();
  expect(clean, recheckOut).not.toBeNull();
  const [secrets, files] = [found![1], found![3]];
  // The narration says "all" for both counts
  expect([found![2], scrubbed![1], scrubbed![2], clean![1]]).toEqual([files, secrets, files, files]);

  await clear();

  // Load the leaking trace before the first beat; the frames before it are trimmed off
  let v = await openTrace('/before.zip');
  await mark(v.getByText(`"${PASSWORD}"`).last(), RED);
  await show('viewer');

  const afterScrub = async () => {
    await shell(scrubCmd, scrubOut);
    v = await openTrace('/after.zip');
    await mark(v.getByText('"[REDACTED:password-fill]"').last(), GREEN);
  };

  if (portrait) {
    await beat('This trace stores the test password in plain text', 4500, 'This Playwright trace stores the test password in plain text.');
    await beat('Anyone who downloads the CI artifact can read it', 4000, 'Anyone who downloads the CI artifact can read it.');
    await show('term');
    await beat(`tracescrub finds ${secrets} secrets\nin ${files} files`, 7000, `Trace scrub finds ${secrets} secrets in these ${files} files.`, () => shell(checkCmd, checkOut));
    await beat('Scrub redacts them in place', 6000, `Scrub redacts all ${secrets}, in place.`, afterScrub);
    await show('viewer');
    await beat('The trace still opens.\nThe password is redacted', 6000, 'The trace still opens, with the password redacted.');
    await beat('This trace no longer stores\nthe test password', 4500, 'This trace no longer stores the test password.');
  } else {
    await beat('This trace stores the test password in plain text', 4500, 'This Playwright trace stores the test password in plain text.');
    await beat('Plus the bearer token, session cookie and API key', 4500, 'It also keeps the bearer token, the session cookie and the API key.', async () => {
      await v.getByText('Network', { exact: true }).click();
      await v.getByText('POST', { exact: true }).click();
      await v.getByText('General', { exact: true }).click();
      await mark(v.getByText(/^Bearer eyJ/).first(), RED);
    });
    await beat('Anyone who downloads the CI artifact can read them', 4000, 'Anyone who downloads the CI artifact can read them.');
    await show('term');
    await beat('tracescrub finds and redacts secrets in Playwright artifacts', 4000, 'Trace scrub finds and redacts secrets in Playwright artifacts.', () => type(checkCmd));
    await beat(`Check: ${secrets} secrets in all ${files} files`, 7500, `Check finds ${secrets} secrets in all ${files} files: trace, report, HAR and storage state.`, () => print(checkOut));
    await beat(`Scrub redacts all ${secrets} in place`, 7000, `Scrub replaces all ${secrets} with a redacted marker, in place.`, afterScrub);
    await show('viewer');
    await beat('The trace still opens. The password is redacted', 7000, 'The scrubbed trace still opens in the trace viewer. The password is redacted.');
    await show('term');
    await clear();
    await beat('Check again: 0 secrets left', 6000, 'Run check again: zero secrets left.', () => shell(checkCmd, recheckOut));
    await beat(`${secrets} found. 0 left. The trace still opens.`, 5500, `${secrets} secrets found, zero left, and the trace still opens.`);
    await beat('npm i -D pw-tracescrub', 4500, 'Install it from npm: P W trace scrub.');
  }

  const length = (Date.now() - start) / 1000;
  const video = page.video()!;
  await context.close();
  server.close();
  rmSync(work, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  await video.saveAs(path.join(outDir, `tracescrub-${testInfo.project.name}.webm`));
  writeFileSync(path.join(outDir, `narration-${testInfo.project.name}.tsv`), cues.join('\n') + '\n');
  // ffmpeg input options that cut the video to the beats
  writeFileSync(path.join(outDir, `cut-${testInfo.project.name}.txt`), `-ss ${((start - recordingStart) / 1000).toFixed(2)} -t ${length.toFixed(2)}\n`);
});
