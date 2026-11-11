/**
 * File format handling: zip archives (trace.zip, report data/*.zip),
 * NDJSON trace entries, JSON documents (HAR, storageState), the HTML report's
 * embedded zip, and plain text.
 */
import JSZip from 'jszip';
import { applyHits, type Detector } from './detector.js';
import { detectKind, scrubJson } from './structural.js';

export interface RawFinding {
  /** Path of the file on disk. */
  file: string;
  /** Entry chain inside archives, e.g. "data/abc.zip!1-trace.trace". Empty for plain files. */
  entry: string;
  /** Line number and/or JSON path inside the entry. */
  location: string;
  rule: string;
  /** The secret itself. Kept in memory only; never printed. */
  value: string;
  harvest: boolean;
}

export interface ProcessContext {
  det: Detector;
  file: string;
  onHit(f: RawFinding): void;
  /**
   * Called for content that was not scanned. `entry` is the archive entry chain,
   * or '' when the whole file was skipped.
   */
  onSkip?(entry: string, reason: string, kind: SkipKind): void;
}

/**
 * Why something was not scanned:
 * - `media`: images, fonts, audio and video. Text rules cannot apply to them; they
 *   are reported as a note only.
 * - `unscanned`: anything else we could not read (unreadable zip, non-UTF-8 text,
 *   other binary formats). These may hide secrets, so they are warned about and
 *   make `check` and `scrub` fail unless `--allow-unscanned` is given.
 */
export type SkipKind = 'media' | 'unscanned';

const MEDIA_EXT = /\.(png|jpe?g|gif|webp|avif|bmp|ico|tiff?|woff2?|ttf|otf|eot|mp4|webm|mov|avi|mp3|wav|ogg)$/i;
const BINARY_EXT = /\.(wasm|pdf|gz|tgz|br|zst|7z|rar)$/i;
const NDJSON_EXT = /\.(trace|network|ndjson|jsonl)$/i;
const JSON_EXT = /\.(json|har|stacks)$/i;
const REPORT_MARKER = 'playwrightReportBase64';
const REPORT_DATA_RE = /(data:application\/zip;base64,)([A-Za-z0-9+/=]+)/;

export function isZip(name: string, buf: Uint8Array): boolean {
  if (/\.zip$/i.test(name)) return true;
  return buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
}

export function decodeText(buf: Uint8Array): string | null {
  const head = buf.subarray(0, 8192);
  if (head.includes(0)) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    return null;
  }
}

function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < offset; i = text.indexOf('\n', i + 1)) line++;
  return line;
}

/**
 * Scan (and rewrite) one blob. Returns the rewritten bytes when something was
 * redacted, or null when the content is unchanged or was not scanned.
 */
export async function processContent(
  name: string,
  buf: Uint8Array,
  ctx: ProcessContext,
  entry = '',
): Promise<Uint8Array | null> {
  if (isZip(name, buf)) return processZip(buf, ctx, entry);
  if (MEDIA_EXT.test(name)) {
    ctx.onSkip?.(entry, 'image or media (not scanned yet)', 'media');
    return null;
  }
  if (BINARY_EXT.test(name)) {
    ctx.onSkip?.(entry, 'binary format that tracescrub cannot read', 'unscanned');
    return null;
  }
  const text = decodeText(buf);
  if (text === null) {
    ctx.onSkip?.(entry, 'not UTF-8 text', 'unscanned');
    return null;
  }
  const out = processText(name, text, ctx, entry);
  if (out instanceof Promise) {
    const r = await out;
    return r === null ? null : Buffer.from(r, 'utf8');
  }
  return out === null ? null : Buffer.from(out, 'utf8');
}

function processText(name: string, text: string, ctx: ProcessContext, entry: string): string | null | Promise<string | null> {
  if (/\.html?$/i.test(name) && text.includes(REPORT_MARKER) && REPORT_DATA_RE.test(text)) {
    return processReportHtml(text, ctx, entry);
  }
  if (NDJSON_EXT.test(name)) return processNdjson(text, ctx, entry);
  const trimmed = text.trimStart();
  if (JSON_EXT.test(name) || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const doc = JSON.parse(text);
      return processJsonDoc(text, doc, ctx, entry);
    } catch {
      if (trimmed.startsWith('{') && text.includes('\n')) return processNdjson(text, ctx, entry);
    }
  }
  return processPlain(text, ctx, entry, 1, '');
}

function processPlain(text: string, ctx: ProcessContext, entry: string, firstLine: number, suffix: string): string | null {
  const hits = ctx.det.scan(text);
  if (hits.length === 0) return null;
  for (const h of hits) {
    ctx.onHit({
      file: ctx.file,
      entry,
      location: `line ${firstLine + lineOf(text, h.start) - 1}${suffix}`,
      rule: h.rule,
      value: h.value,
      harvest: h.harvest,
    });
  }
  return applyHits(text, hits);
}

function processJsonDoc(text: string, doc: unknown, ctx: ProcessContext, entry: string): string | null {
  const res = scrubJson(doc, ctx.det, detectKind(doc));
  for (const h of res.hits) {
    ctx.onHit({ file: ctx.file, entry, location: h.path, rule: h.rule, value: h.value, harvest: h.harvest });
  }
  if (!res.changed) return null;
  const indentMatch = /^[[{]\r?\n([ \t]+)/.exec(text);
  const indent = indentMatch ? indentMatch[1] : undefined;
  const trailing = /\r?\n$/.exec(text)?.[0] ?? '';
  return JSON.stringify(res.value, null, indent) + trailing;
}

function processNdjson(text: string, ctx: ProcessContext, entry: string): string | null {
  const lines = text.split('\n');
  let changed = false;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (!line.trim()) continue;
    let doc: unknown;
    let parsed = false;
    try {
      doc = JSON.parse(line);
      parsed = true;
    } catch {
      /* fall back to plain text */
    }
    let out: string | null;
    if (parsed) {
      const res = scrubJson(doc, ctx.det, 'trace');
      for (const h of res.hits) {
        ctx.onHit({
          file: ctx.file,
          entry,
          location: `line ${i + 1} ${h.path}`,
          rule: h.rule,
          value: h.value,
          harvest: h.harvest,
        });
      }
      out = res.changed ? JSON.stringify(res.value) : null;
    } else {
      out = processPlain(line, ctx, entry, i + 1, '');
    }
    if (out !== null) {
      lines[i] = raw.endsWith('\r') ? out + '\r' : out;
      changed = true;
    }
  }
  return changed ? lines.join('\n') : null;
}

/** Scan every embedded zip in the HTML report; the first is "<embedded report>", later ones "<embedded report #2>"... */
async function processReportHtml(text: string, ctx: ProcessContext, entry: string): Promise<string | null> {
  const re = new RegExp(REPORT_DATA_RE.source, 'g');
  let result = '';
  let pos = 0;
  let n = 0;
  let changed = false;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    n++;
    const inner = Buffer.from(m[2], 'base64');
    const chain = `${entry ? entry + '!' : ''}<embedded report${n > 1 ? ` #${n}` : ''}>`;
    const out = await processZip(inner, ctx, chain);
    if (!out) continue;
    result += text.slice(pos, m.index) + m[1] + Buffer.from(out).toString('base64');
    pos = m.index + m[0].length;
    changed = true;
  }
  return changed ? result + text.slice(pos) : null;
}

export async function processZip(buf: Uint8Array, ctx: ProcessContext, entry: string): Promise<Uint8Array | null> {
  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(buf);
  } catch (e) {
    ctx.onSkip?.(entry, `unreadable zip: ${(e as Error).message}`, 'unscanned');
    return null;
  }
  let changed = false;
  for (const f of Object.values(zip.files)) {
    if (f.dir) continue;
    const data = await f.async('uint8array');
    const chain = entry ? `${entry}!${f.name}` : f.name;
    const out = await processContent(f.name, data, ctx, chain);
    if (out) {
      zip.file(f.name, out, {
        binary: true,
        createFolders: false,
        date: f.date,
        comment: f.comment ?? undefined,
        unixPermissions: f.unixPermissions ?? undefined,
        dosPermissions: f.dosPermissions ?? undefined,
      });
      changed = true;
    }
  }
  if (!changed) return null;
  return zip.generateAsync({
    type: 'uint8array',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
  });
}
