import path from 'node:path';
import { unscannedOf, type FileResult } from './engine.js';

export interface Summary {
  files: number;
  filesWithFindings: number;
  findings: number;
  byRule: Record<string, number>;
  filesWritten: number;
  /** Entries or files that were not scanned and may hide secrets (unreadable zips, non-UTF-8 text...). */
  unscanned: number;
  /** Images, fonts, audio and video that were not scanned. */
  media: number;
}

export function summarize(results: FileResult[]): Summary {
  const byRule: Record<string, number> = {};
  let findings = 0;
  for (const r of results) {
    for (const f of r.findings) {
      byRule[f.rule] = (byRule[f.rule] ?? 0) + 1;
      findings++;
    }
  }
  return {
    files: results.length,
    filesWithFindings: results.filter((r) => r.findings.length > 0).length,
    findings,
    byRule: Object.fromEntries(Object.entries(byRule).sort((a, b) => b[1] - a[1])),
    filesWritten: results.filter((r) => r.written).length,
    unscanned: results.reduce((n, r) => n + unscannedOf(r).length, 0),
    media: results.reduce((n, r) => n + r.skipped.filter((x) => x.kind === 'media').length, 0),
  };
}

export const rel = (p: string) => {
  const r = path.relative(process.cwd(), p);
  return r && !r.startsWith('..') ? r : p;
};

/** "file" or "file!entry!inner" for a skipped item, for warnings. */
export function skipLocation(file: string, entry: string): string {
  return entry ? `${rel(file)}!${entry}` : rel(file);
}

const items = (n: number) => `${n} item${n === 1 ? '' : 's'}`;

export function formatHuman(
  results: FileResult[],
  opts: { all?: boolean; mode: 'check' | 'scrub'; allowUnscanned?: boolean },
): string {
  const lines: string[] = [];
  const limit = opts.all ? Infinity : 25;
  for (const r of results) {
    if (r.findings.length === 0) continue;
    lines.push(rel(r.file));
    for (const f of r.findings.slice(0, limit)) {
      const where = [f.entry, f.location].filter(Boolean).join(' ');
      lines.push(`  ${where}  ${f.rule}  ${f.preview}`);
    }
    if (r.findings.length > limit) {
      lines.push(`  ... and ${r.findings.length - limit} more (use --all or --json to list everything)`);
    }
    lines.push('');
  }
  const s = summarize(results);
  const rules = Object.entries(s.byRule)
    .map(([k, v]) => `${k}: ${v}`)
    .join(', ');
  if (opts.mode === 'check') {
    if (s.findings === 0 && s.unscanned > 0) lines.push(`No secrets found in the scanned content of ${s.files} file(s).`);
    else if (s.findings === 0) lines.push(`No secrets found in ${s.files} file(s).`);
    else lines.push(`Found ${s.findings} potential secret(s) in ${s.filesWithFindings} of ${s.files} file(s). (${rules})`);
  } else {
    lines.push(
      s.findings === 0
        ? `Nothing to scrub in ${s.files} file(s).`
        : `Scrubbed ${s.findings} secret(s) in ${s.filesWritten} of ${s.files} file(s). (${rules})`,
    );
  }
  if (s.unscanned > 0) {
    const consequence = opts.allowUnscanned
      ? 'accepted because of --allow-unscanned'
      : opts.mode === 'check'
        ? 'the check fails; pass --allow-unscanned to accept this'
        : 'exit code 2; pass --allow-unscanned to accept this';
    lines.push(`Warning: ${items(s.unscanned)} could not be scanned and may contain secrets (listed on stderr; ${consequence}).`);
  }
  if (s.media > 0) {
    lines.push(`Note: ${s.media} image/media entr${s.media === 1 ? 'y was' : 'ies were'} not scanned (screenshots and screencast frames are not redacted yet).`);
  }
  return lines.join('\n');
}

export function formatJson(results: FileResult[], mode: 'check' | 'scrub'): string {
  return JSON.stringify(
    {
      tool: 'tracescrub',
      mode,
      summary: summarize(results),
      findings: results.flatMap((r) => r.findings),
      skipped: results.flatMap((r) => r.skipped.map((s) => ({ file: r.file, ...s }))),
    },
    null,
    2,
  );
}
