import { Command, CommanderError, Option } from 'commander';
import { cp, mkdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { buildDetectorOptions } from './config.js';
import { discover } from './discover.js';
import { scanFiles, unscannedOf, type FileResult } from './engine.js';
import { UsageError } from './errors.js';
import { formatHuman, formatJson, skipLocation } from './output.js';
import { VERSION } from './version.js';

export interface Io {
  out(text: string): void;
  err(text: string): void;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

const defaultIo: Io = {
  out: (t) => process.stdout.write(t.endsWith('\n') ? t : t + '\n'),
  err: (t) => process.stderr.write(t.endsWith('\n') ? t : t + '\n'),
};

interface CommonOpts {
  env?: string[];
  envFile?: string[];
  config?: string;
  json?: boolean;
  jsonOut?: string;
  all?: boolean;
  propagate?: boolean;
  allowUnscanned?: boolean;
}

const collect = (v: string, prev: string[] = []) => [...prev, v];

function addCommon(cmd: Command): Command {
  return cmd
    .option('--env <names>', 'comma-separated env var names whose values are secrets (repeatable)', collect)
    .option('--env-file <file>', 'dotenv file whose values are secrets (repeatable)', collect)
    .option('--config <file>', 'config file (default: ./tracescrub.config.json if present)')
    .option('--json', 'machine-readable output')
    .option('--json-out <file>', 'also write the JSON report to a file')
    .option('--all', 'list every finding instead of the first 25 per file')
    .addOption(new Option('--no-propagate', 'do not redact harvested secrets (e.g. typed passwords) everywhere else'))
    .option('--allow-unscanned', 'do not fail when some content could not be scanned (unreadable zips, non-UTF-8 text)');
}

async function prepareOut(paths: string[], outDir: string): Promise<string[]> {
  const outAbs = path.resolve(outDir);
  const dests: string[] = [];
  const seen = new Set<string>();
  for (const p of paths) {
    const abs = path.resolve(p);
    const st = await stat(abs).catch(() => {
      throw new UsageError(`path not found: ${p}`);
    });
    if (st.isDirectory() && (outAbs === abs || outAbs.startsWith(abs + path.sep))) {
      throw new UsageError(`--out ${outDir} must not be inside the input directory ${p}`);
    }
    const dest = path.join(outAbs, path.basename(abs));
    if (seen.has(dest)) throw new UsageError(`two inputs share the name ${path.basename(abs)}; scrub them separately`);
    seen.add(dest);
    dests.push(dest);
  }
  await mkdir(outAbs, { recursive: true });
  for (let i = 0; i < paths.length; i++) {
    await cp(path.resolve(paths[i]), dests[i], { recursive: true, force: true });
  }
  return dests;
}

/** Warn on stderr about every skipped item that is not an image or other media. Returns how many there were. */
function warnUnscanned(results: FileResult[], io: Io): number {
  let n = 0;
  for (const r of results) {
    for (const s of unscannedOf(r)) {
      io.err(`tracescrub: warning: not scanned: ${skipLocation(r.file, s.entry)} (${s.reason})`);
      n++;
    }
  }
  return n;
}

export async function main(argv: string[], io: Io = defaultIo): Promise<number> {
  let exitCode = 0;
  const program = new Command();
  program
    .name('tracescrub')
    .description('Find and redact secrets in Playwright traces, HTML reports, HAR files and storageState JSON.')
    .version(VERSION)
    .exitOverride()
    .showHelpAfterError()
    .configureOutput({ writeOut: (s) => io.out(s), writeErr: (s) => io.err(s) });

  const detOpts = (o: CommonOpts) =>
    buildDetectorOptions({
      env: o.env,
      envFile: o.envFile,
      config: o.config,
      cwd: io.cwd,
      environment: io.env,
      warn: (m) => io.err(`tracescrub: warning: ${m}`),
    });

  addCommon(
    program
      .command('check')
      .description('report secrets; exit 1 if any are found or content could not be scanned, 0 if clean, 2 on usage errors')
      .argument('<paths...>', 'files or directories (test-results, playwright-report, *.zip, *.har, *.json)'),
  ).action(async (paths: string[], o: CommonOpts) => {
    const options = detOpts(o);
    const files = await discover(paths);
    const results = await scanFiles(files, options, { scrub: false, propagate: o.propagate });
    const unscanned = warnUnscanned(results, io);
    io.out(o.json ? formatJson(results, 'check') : formatHuman(results, { all: o.all, mode: 'check', allowUnscanned: o.allowUnscanned }));
    if (o.jsonOut) await writeFile(o.jsonOut, formatJson(results, 'check') + '\n');
    const found = results.some((r) => r.findings.length > 0);
    exitCode = found || (unscanned > 0 && !o.allowUnscanned) ? 1 : 0;
  });

  addCommon(
    program
      .command('scrub')
      .description('rewrite files replacing each secret with [REDACTED:<rule>]; exit 2 if some content could not be scanned')
      .argument('<paths...>', 'files or directories to scrub')
      .option('--out <dir>', 'write scrubbed copies under this directory')
      .option('--in-place', 'overwrite the input files'),
  ).action(async (paths: string[], o: CommonOpts & { out?: string; inPlace?: boolean }) => {
    if (Boolean(o.out) === Boolean(o.inPlace)) throw new UsageError('scrub needs exactly one of --out <dir> or --in-place');
    const options = detOpts(o);
    await discover(paths); // validates the inputs before copying anything
    const targets = o.out ? await prepareOut(paths, o.out) : paths;
    const files = await discover(targets);
    const results = await scanFiles(files, options, { scrub: true, propagate: o.propagate });
    const unscanned = warnUnscanned(results, io);
    io.out(o.json ? formatJson(results, 'scrub') : formatHuman(results, { all: o.all, mode: 'scrub', allowUnscanned: o.allowUnscanned }));
    if (o.jsonOut) await writeFile(o.jsonOut, formatJson(results, 'scrub') + '\n');
    if (o.out && !o.json) io.out(`Output: ${path.resolve(o.out)}`);
    exitCode = unscanned > 0 && !o.allowUnscanned ? 2 : 0;
  });

  try {
    await program.parseAsync(argv, { from: 'user' });
    return exitCode;
  } catch (e) {
    if (e instanceof CommanderError) {
      if (e.code === 'commander.helpDisplayed' || e.code === 'commander.version' || e.code === 'commander.help') return 0;
      return 2;
    }
    if (e instanceof UsageError) {
      io.err(`tracescrub: ${e.message}`);
      return 2;
    }
    io.err(`tracescrub: error: ${(e as Error).stack ?? String(e)}`);
    return 3;
  }
}
