// Regenerates test/fixtures/ from a real Playwright run.
//
//   npx playwright install chromium   (once)
//   npm run fixtures:gen
//
// The run records a trace, a HAR, an HTML report and a storageState file from
// a fake login page (see tests/login.spec.ts). Afterwards this script:
//   - replaces absolute local paths in the artifacts with /work/tracescrub
//   - trims the HTML report's index.html down to the embedded results zip
//     (the full report app is ~500 KB of JavaScript and holds no test data)
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';

const here = import.meta.dirname;
const root = path.resolve(here, '..');
const out = path.join(here, '.out');
const dest = path.join(root, 'test', 'fixtures');

rmSync(out, { recursive: true, force: true });
execFileSync('npx', ['playwright', 'test', '-c', path.join(here, 'playwright.config.ts')], {
  cwd: root,
  stdio: 'inherit',
});

const replacements = [
  [root, '/work/tracescrub'],
  [os.homedir(), '/home/user'],
];
const normalize = (text) => replacements.reduce((t, [from, to]) => t.split(from).join(to), text);

async function normalizeZip(buf) {
  const zip = await JSZip.loadAsync(buf);
  for (const f of Object.values(zip.files)) {
    if (f.dir || /\.(png|jpe?g)$/i.test(f.name)) continue;
    const text = await f.async('string');
    const n = normalize(text);
    if (n !== text) zip.file(f.name, n, { date: f.date, createFolders: false });
  }
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

rmSync(dest, { recursive: true, force: true });
mkdirSync(path.join(dest, 'report', 'data'), { recursive: true });

// trace.zip from test-results
const resultsDir = path.join(out, 'test-results');
const testDir = readdirSync(resultsDir).find((d) => !d.startsWith('.'));
writeFileSync(path.join(dest, 'trace.zip'), await normalizeZip(readFileSync(path.join(resultsDir, testDir, 'trace.zip'))));

// HAR and storageState
writeFileSync(path.join(dest, 'login.har'), normalize(readFileSync(path.join(out, 'login.har'), 'utf8')));
cpSync(path.join(out, 'storageState.json'), path.join(dest, 'storageState.json'));

// HTML report: data/*.zip plus a trimmed index.html that keeps the embedded results zip
const reportDir = path.join(out, 'report');
for (const f of readdirSync(path.join(reportDir, 'data'))) {
  if (!f.endsWith('.zip')) continue;
  writeFileSync(path.join(dest, 'report', 'data', f), await normalizeZip(readFileSync(path.join(reportDir, 'data', f))));
}
const html = readFileSync(path.join(reportDir, 'index.html'), 'utf8');
const m = /<(script|template) id="playwrightReportBase64"[^>]*>data:application\/zip;base64,([A-Za-z0-9+/=]+)<\/\1>/.exec(html);
if (!m) throw new Error('could not find the embedded report zip in index.html');
const embedded = (await normalizeZip(Buffer.from(m[2], 'base64'))).toString('base64');
writeFileSync(
  path.join(dest, 'report', 'index.html'),
  [
    '<!DOCTYPE html>',
    '<html><head><meta charset="UTF-8"><title>Playwright Test Report</title></head>',
    '<body><div id="root"></div>',
    '<!-- trimmed by fixtures-gen: the report app bundle was removed, the embedded results zip is unchanged apart from path normalization -->',
    `<${m[1]} id="playwrightReportBase64">data:application/zip;base64,${embedded}</${m[1]}>`,
    '</body></html>',
    '',
  ].join('\n'),
);

console.log(`fixtures written to ${path.relative(root, dest)}`);
