import JSZip from 'jszip';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { allText, FIXTURES, PLANTED, PLANTED_VALUES, run } from './helpers.js';

const fx = (...p: string[]) => path.join(FIXTURES, ...p);
const tmp = (prefix = 'tracescrub-') => mkdtempSync(path.join(os.tmpdir(), prefix));
const reportZip = () => fx('report', 'data', readdirSync(fx('report', 'data')).find((f) => f.endsWith('.zip'))!);

interface JsonOut {
  summary: { findings: number; byRule: Record<string, number> };
  findings: { file: string; entry: string; location: string; rule: string; preview: string }[];
}

describe('check', () => {
  it.each([
    ['trace.zip', ['password-fill', 'password-input', 'authorization', 'cookie', 'jwt', 'sensitive-key']],
    ['login.har', ['authorization', 'cookie', 'jwt', 'sensitive-key']],
    ['storageState.json', ['cookie', 'local-storage']],
    ['report', ['password-fill', 'password-input', 'authorization', 'cookie']],
  ])('finds the planted secrets in %s and exits 1', async (name, rules) => {
    const r = await run(['check', fx(name), '--json']);
    expect(r.code).toBe(1);
    const out = JSON.parse(r.stdout) as JsonOut;
    expect(out.summary.findings).toBeGreaterThan(0);
    for (const rule of rules) expect(Object.keys(out.summary.byRule)).toContain(rule);
  });

  it('reports the password typed into the login form inside the trace', async () => {
    const out = JSON.parse((await run(['check', fx('trace.zip'), '--json'])).stdout) as JsonOut;
    const fill = out.findings.find((f) => f.rule === 'password-fill' && f.entry.endsWith('-trace.trace'));
    expect(fill).toMatchObject({ entry: expect.stringMatching(/^\d+-trace\.trace$/), location: expect.stringMatching(/^line \d+ \$\.params\.value$/) });
    expect(fill!.preview).toBe('tsk_****** (24 chars)');
    const snap = out.findings.find((f) => f.rule === 'password-input');
    expect(snap?.location).toMatch(/__playwright_value_$/);
  });

  it('finds the step title in the embedded HTML report data', async () => {
    const out = JSON.parse((await run(['check', fx('report', 'index.html'), '--json'])).stdout) as JsonOut;
    expect(out.findings.some((f) => f.entry.startsWith('<embedded report>!') && f.rule === 'password-fill')).toBe(true);
  });

  it('never prints a planted secret in human or JSON output', async () => {
    for (const args of [['check', FIXTURES, '--all'], ['check', FIXTURES, '--json']]) {
      const r = await run(args);
      expect(r.code).toBe(1);
      for (const secret of PLANTED_VALUES) {
        expect(r.stdout).not.toContain(secret);
        expect(r.stderr).not.toContain(secret);
        // not even a long prefix
        expect(r.stdout).not.toContain(secret.slice(0, 8));
      }
    }
  });

  it('prints a readable report', async () => {
    const r = await run(['check', fx('storageState.json')]);
    expect(r.stdout).toContain('$.cookies[0].value  cookie  tsk_****** (27 chars)');
    expect(r.stdout).toMatch(/Found \d+ potential secret\(s\) in 1 of 1 file\(s\)/);
  });

  it('treats --env values as known secrets, ignoring short values', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'notes.txt'), `the password is ${PLANTED.password}\nshort: abc\n`);
    const r = await run(['check', dir, '--env', 'TEST_PASSWORD,SHORT', '--json'], { TEST_PASSWORD: PLANTED.password, SHORT: 'abc' });
    expect(r.code).toBe(1);
    const out = JSON.parse(r.stdout) as JsonOut;
    expect(out.findings).toEqual([expect.objectContaining({ rule: 'env:TEST_PASSWORD', location: 'line 1' })]);
  });

  it('reads --env-file values', async () => {
    const dir = tmp();
    const envFile = path.join(dir, 'test.env');
    writeFileSync(envFile, `LOGIN_PASSWORD=${PLANTED.password}\n`);
    writeFileSync(path.join(dir, 'log.txt'), `typed ${PLANTED.password}`);
    const r = await run(['check', path.join(dir, 'log.txt'), '--env-file', envFile]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('env:LOGIN_PASSWORD');
  });

  it('honours a config allowlist', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ cookies: [{ name: 'session', value: 'allowed-session-value' }] }));
    writeFileSync(path.join(dir, 'cfg.json'), JSON.stringify({ allowlist: ['allowed-session-value'] }));
    expect((await run(['check', path.join(dir, 'state.json')])).code).toBe(1);
    expect((await run(['check', path.join(dir, 'state.json'), '--config', path.join(dir, 'cfg.json')])).code).toBe(0);
  });

  it('writes a JSON report with --json-out', async () => {
    const dir = tmp();
    const file = path.join(dir, 'report.json');
    const r = await run(['check', fx('login.har'), '--json-out', file]);
    expect(r.code).toBe(1);
    const out = JSON.parse(readFileSync(file, 'utf8')) as JsonOut;
    expect(out.summary.findings).toBeGreaterThan(0);
    for (const secret of PLANTED_VALUES) expect(readFileSync(file, 'utf8')).not.toContain(secret);
  });

  it('exits 0 on clean input', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'clean.json'), JSON.stringify({ hello: 'world', theme: 'dark' }));
    const r = await run(['check', dir]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('No secrets found');
  });

  it.each([
    [['check']],
    [['check', '/definitely/not/here']],
    [['scrub', 'x']],
    [['scrub', 'x', '--out', 'y', '--in-place']],
    [['check', '.', '--config', '/definitely/not/here.json']],
    [['bogus']],
  ])('exits 2 on usage error %j', async (args) => {
    const dir = tmp();
    const r = await run(args.map((a) => (a === 'x' ? dir : a)));
    expect(r.code).toBe(2);
  });
});

describe('content that cannot be scanned', () => {
  const latin1 = Buffer.from([0x70, 0x61, 0x73, 0x73, 0x3d, 0xe9, 0xe8, 0xff, 0x0a]); // not valid UTF-8
  const brokenZip = Buffer.from('PK\u0003\u0004 this is not really a zip archive');

  async function mixedZip(): Promise<Buffer> {
    const zip = new JSZip();
    zip.file('notes.txt', 'nothing secret here\n');
    zip.file('legacy.log', latin1);
    zip.file('shot.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
    return Buffer.from(await zip.generateAsync({ type: 'uint8array' }));
  }

  it('check warns about an unreadable zip and fails', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'broken.zip'), brokenZip);
    writeFileSync(path.join(dir, 'clean.json'), JSON.stringify({ hello: 'world' }));
    const r = await run(['check', dir]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/warning: not scanned: .*broken\.zip \(unreadable zip/);
    expect(r.stdout).not.toContain('No secrets found in 2 file(s).');
    expect(r.stdout).toContain('No secrets found in the scanned content of 2 file(s).');
    expect(r.stdout).toMatch(/1 item could not be scanned .*--allow-unscanned/);
  });

  it('check warns about non-UTF-8 text files and fails', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'legacy.log'), latin1);
    const r = await run(['check', dir, '--json']);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/not scanned: .*legacy\.log \(not UTF-8 text\)/);
    const out = JSON.parse(r.stdout);
    expect(out.summary).toMatchObject({ findings: 0, unscanned: 1 });
    expect(out.skipped).toEqual([expect.objectContaining({ entry: '', kind: 'unscanned' })]);
  });

  it('warns about unscanned zip entries but not about images', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'trace.zip'), await mixedZip());
    const r = await run(['check', dir, '--json']);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/not scanned: .*trace\.zip!legacy\.log \(not UTF-8 text\)/);
    expect(r.stderr).not.toContain('shot.png');
    expect(JSON.parse(r.stdout).summary).toMatchObject({ unscanned: 1, media: 1 });
  });

  it('check passes with --allow-unscanned but still warns', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'broken.zip'), brokenZip);
    const r = await run(['check', dir, '--allow-unscanned']);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain('not scanned');
    expect(r.stdout).toContain('accepted because of --allow-unscanned');
  });

  it('check still exits 1 for findings when --allow-unscanned is set', async () => {
    const r = await run(['check', fx('storageState.json'), '--allow-unscanned']);
    expect(r.code).toBe(1);
  });

  it('scrub exits 2 when an input cannot be processed', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'broken.zip'), brokenZip);
    cpSync(fx('storageState.json'), path.join(dir, 'state.json'));
    const r = await run(['scrub', dir, '--in-place']);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/not scanned: .*broken\.zip/);
    // what could be scrubbed still is
    expect(readFileSync(path.join(dir, 'state.json'), 'utf8')).not.toContain(PLANTED.sessionCookie);
    expect((await run(['scrub', dir, '--in-place', '--allow-unscanned'])).code).toBe(0);
  });

  it('scrub --out leaves files it could not scan out of the output', async () => {
    const src = tmp();
    const out = tmp('tracescrub-out-');
    writeFileSync(path.join(src, 'broken.zip'), brokenZip);
    writeFileSync(path.join(src, 'legacy.log'), latin1);
    writeFileSync(path.join(src, 'trace.zip'), await mixedZip());
    cpSync(fx('storageState.json'), path.join(src, 'state.json'));
    const name = path.basename(src);
    const r = await run(['scrub', src, '--out', out, '--json']);
    expect(r.code).toBe(2);
    expect(existsSync(path.join(out, name, 'broken.zip'))).toBe(false);
    expect(existsSync(path.join(out, name, 'legacy.log'))).toBe(false);
    expect(r.stderr).toMatch(/not copied to --out \(could not be scanned\): .*broken\.zip/);
    expect(r.stderr).toMatch(/not copied to --out \(could not be scanned\): .*legacy\.log/);
    // scanned files are still written, scrubbed
    expect(readFileSync(path.join(out, name, 'state.json'), 'utf8')).not.toContain(PLANTED.sessionCookie);
    // a zip that was only partly scanned is kept; its unscanned entry is listed instead
    expect(existsSync(path.join(out, name, 'trace.zip'))).toBe(true);
    expect(r.stderr).toMatch(/not scanned: .*trace\.zip!legacy\.log/);
    const json = JSON.parse(r.stdout);
    expect(json.summary.filesNotCopied).toBe(2);
    expect(json.notCopied).toHaveLength(2);
    // the originals are untouched
    expect(existsSync(path.join(src, 'broken.zip'))).toBe(true);
  });

  it('scrub --out reports left-out files in the human summary', async () => {
    const src = tmp();
    writeFileSync(path.join(src, 'broken.zip'), brokenZip);
    const r = await run(['scrub', src, '--out', tmp('tracescrub-out-'), '--allow-unscanned']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('Not copied to the output: 1 file(s) that could not be scanned');
  });

  it('does not warn about images and media inside the fixtures', async () => {
    const r = await run(['check', FIXTURES]);
    expect(r.stderr).not.toContain('not scanned');
    expect(r.stdout).toMatch(/Note: \d+ image\/media entries were not scanned/);
  });
});

describe('scrub', () => {
  let outDir: string;
  beforeAll(async () => {
    outDir = tmp('tracescrub-out-');
    const r = await run(['scrub', FIXTURES, '--out', outDir]);
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/Scrubbed \d+ secret\(s\) in 4 of 5 file\(s\)|Scrubbed \d+ secret\(s\) in 5 of 5 file\(s\)/);
  });
  const scrubbed = (...p: string[]) => path.join(outDir, 'fixtures', ...p);

  it('produces output that passes check', async () => {
    const r = await run(['check', path.join(outDir, 'fixtures')]);
    expect(r.stdout).toContain('No secrets found');
    expect(r.code).toBe(0);
  });

  it('removes every planted value from every file, zip entry and embedded zip', async () => {
    for (const rel of ['trace.zip', 'login.har', 'storageState.json', 'report/index.html', path.relative(FIXTURES, reportZip())]) {
      const texts = await allText(rel, readFileSync(scrubbed(rel)));
      const joined = texts.join('\n');
      for (const secret of PLANTED_VALUES) expect(joined, `${rel} still contains a planted value`).not.toContain(secret);
      expect(joined).toContain('[REDACTED:');
    }
  });

  it('keeps the original files untouched when using --out', async () => {
    const texts = (await allText('trace.zip', readFileSync(fx('trace.zip')))).join('\n');
    expect(texts).toContain(PLANTED.password);
  });

  it('keeps the zip valid with the same entry list', async () => {
    for (const rel of ['trace.zip', path.relative(FIXTURES, reportZip())]) {
      const before = await JSZip.loadAsync(readFileSync(fx(rel)));
      const after = await JSZip.loadAsync(readFileSync(scrubbed(rel)));
      expect(Object.keys(after.files)).toEqual(Object.keys(before.files));
      // binary entries (screenshots) are byte-identical
      for (const name of Object.keys(before.files).filter((n) => n.endsWith('.jpeg'))) {
        expect(Buffer.from(await after.file(name)!.async('uint8array'))).toEqual(
          Buffer.from(await before.file(name)!.async('uint8array')),
        );
      }
    }
  });

  it('keeps every NDJSON line of the trace parseable', async () => {
    const zip = await JSZip.loadAsync(readFileSync(scrubbed('trace.zip')));
    const ndjson = Object.keys(zip.files).filter((n) => /\.(trace|network)$/.test(n));
    expect(ndjson.length).toBeGreaterThanOrEqual(3);
    let lines = 0;
    for (const name of ndjson) {
      const text = await zip.file(name)!.async('string');
      for (const line of text.split('\n').filter((l) => l.trim())) {
        expect(() => JSON.parse(line), `${name}: ${line.slice(0, 80)}`).not.toThrow();
        lines++;
      }
    }
    expect(lines).toBeGreaterThan(20);
    // the trace still has its context-options header and action events
    const main = await zip.file(ndjson.find((n) => n.endsWith('.trace') && n !== 'test.trace')!)!.async('string');
    expect(main).toContain('"type":"context-options"');
    expect(main).toContain('"method":"fill"');
  });

  it('keeps JSON files valid and formatted', () => {
    const state = JSON.parse(readFileSync(scrubbed('storageState.json'), 'utf8'));
    expect(state.cookies[0].value).toBe('[REDACTED:cookie]');
    expect(state.cookies[1]).toMatchObject({ name: 'locale', value: 'en-GB' });
    expect(state.origins[0].localStorage).toEqual([
      { name: 'auth_token', value: '[REDACTED:local-storage]' },
      { name: 'theme', value: 'dark' },
    ]);
    expect(readFileSync(scrubbed('storageState.json'), 'utf8')).toMatch(/^\{\n  "cookies"/);
    const har = JSON.parse(readFileSync(scrubbed('login.har'), 'utf8'));
    expect(har.log.entries.length).toBeGreaterThan(0);
  });

  it('is idempotent', async () => {
    const r = await run(['scrub', path.join(outDir, 'fixtures'), '--in-place']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('Nothing to scrub');
  });

  it('scrubs in place', async () => {
    const dir = tmp();
    cpSync(fx('storageState.json'), path.join(dir, 'state.json'));
    expect((await run(['scrub', path.join(dir, 'state.json'), '--in-place'])).code).toBe(0);
    expect(readFileSync(path.join(dir, 'state.json'), 'utf8')).not.toContain(PLANTED.sessionCookie);
    expect((await run(['check', dir])).code).toBe(0);
  });

  it('refuses an --out directory inside the input', async () => {
    const dir = tmp();
    cpSync(fx('storageState.json'), path.join(dir, 'state.json'));
    expect((await run(['scrub', dir, '--out', path.join(dir, 'out')])).code).toBe(2);
  });
});
