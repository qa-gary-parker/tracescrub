import { readFile, rename, writeFile } from 'node:fs/promises';
import { Detector, type DetectorOptions } from './detector.js';
import { processContent, type RawFinding, type SkipKind } from './formats.js';
import { mask } from './mask.js';

export interface Finding {
  file: string;
  /** Entry chain inside archives (e.g. "data/abc.zip!1-trace.trace"); empty for plain files. */
  entry: string;
  /** Line and/or JSON path inside the file or entry. */
  location: string;
  rule: string;
  /** Masked preview. Never the full secret. */
  preview: string;
}

export interface FileResult {
  file: string;
  findings: Finding[];
  /** Whether the file was rewritten (scrub mode only). */
  written: boolean;
  /** Content that was not scanned. `entry` is '' when the whole file was skipped. */
  skipped: { entry: string; reason: string; kind: SkipKind }[];
  /** `scrub --out` only: the file could not be scanned, so it was left out of the output directory. */
  notCopied?: boolean;
}

/** Skipped content that may hide secrets (not images or other media). */
export function unscannedOf(r: FileResult): FileResult['skipped'] {
  return r.skipped.filter((s) => s.kind === 'unscanned');
}

/** True when the file as a whole could not be scanned (not media). */
export function wholeFileUnscanned(r: FileResult): boolean {
  return r.skipped.some((s) => s.entry === '' && s.kind === 'unscanned');
}

export interface ScanOptions {
  scrub: boolean;
  /** Harvest secrets found structurally (password fills, auth headers...) and redact them everywhere. Default true. */
  propagate?: boolean;
}

const toFinding = (f: RawFinding): Finding => ({
  file: f.file,
  entry: f.entry,
  location: f.location,
  rule: f.rule,
  preview: mask(f.value),
});

/**
 * Scan (and optionally scrub in place) a list of files.
 *
 * Pass 1 harvests secrets that were found by structure (for example the
 * value typed into a password field) so that pass 2 can redact the same
 * value wherever else it appears: DOM snapshots, log lines, step titles,
 * request bodies, other files.
 */
export async function scanFiles(files: string[], detOpts: DetectorOptions, opts: ScanOptions): Promise<FileResult[]> {
  const det = new Detector(detOpts);
  if (opts.propagate !== false) {
    for (let round = 0; round < 3; round++) {
      const before = det.knownCount;
      for (const file of files) {
        const buf = await readFile(file);
        await processContent(file, buf, {
          det,
          file,
          onHit: (h) => {
            if (h.harvest) det.addKnown(h.value, h.rule);
          },
        });
      }
      if (det.knownCount === before) break;
    }
  }

  const results: FileResult[] = [];
  for (const file of files) {
    const buf = await readFile(file);
    const raw: RawFinding[] = [];
    const skipped: FileResult['skipped'] = [];
    const out = await processContent(file, buf, {
      det,
      file,
      onHit: (h) => raw.push(h),
      onSkip: (entry, reason, kind) => skipped.push({ entry, reason, kind }),
    });
    let written = false;
    if (opts.scrub && out) {
      const tmp = `${file}.tracescrub-tmp`;
      await writeFile(tmp, out);
      await rename(tmp, file);
      written = true;
    }
    results.push({ file, findings: raw.map(toFinding), written, skipped });
  }
  return results;
}

/** Convenience: scan a single in-memory string with default rules. Returns masked findings. */
export function scanText(text: string, detOpts: DetectorOptions = {}): { rule: string; preview: string; start: number; end: number }[] {
  const det = new Detector(detOpts);
  return det.scan(text).map((h) => ({ rule: h.rule, preview: mask(h.value), start: h.start, end: h.end }));
}
