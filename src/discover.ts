import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { UsageError } from './errors.js';

const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);
const SCAN_EXT = /\.(zip|har|json|trace|network|ndjson|jsonl|md|txt|log)$/i;
const REPORT_MARKER = 'playwrightReportBase64';

async function wanted(file: string): Promise<boolean> {
  if (SCAN_EXT.test(file)) return true;
  if (/\.html?$/i.test(file)) {
    // Only the HTML report's index.html (it embeds a zip of test results).
    const text = await readFile(file, 'utf8');
    return text.includes(REPORT_MARKER);
  }
  return false;
}

async function walk(dir: string, out: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) await walk(p, out);
    } else if (e.isFile() && (await wanted(p))) {
      out.push(p);
    }
  }
}

/**
 * Expand the given paths into the list of files to scan. Files named
 * explicitly are always scanned; directories are walked recursively for
 * trace zips, report folders, HAR, JSON (storageState) and NDJSON files.
 */
export async function discover(paths: string[]): Promise<string[]> {
  if (paths.length === 0) throw new UsageError('no paths given');
  const out: string[] = [];
  for (const p of paths) {
    let st;
    try {
      st = await stat(p);
    } catch {
      throw new UsageError(`path not found: ${p}`);
    }
    if (st.isDirectory()) await walk(p, out);
    else out.push(p);
  }
  return [...new Set(out)];
}
