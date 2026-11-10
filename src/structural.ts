/**
 * Structure-aware scanning of parsed JSON documents: HAR files, Playwright
 * trace events (NDJSON lines), storageState files and generic JSON.
 */
import { applyHits, type Detector } from './detector.js';
import {
  authorizationSpans,
  cookieHeaderSpans,
  isRedacted,
  isTrivialValue,
  PASSWORD_SELECTOR_RE,
  type Span,
} from './rules.js';

export type DocKind = 'har' | 'trace' | 'storage' | 'json';

export interface JsonHit {
  path: string;
  rule: string;
  value: string;
  harvest: boolean;
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const childPath = (path: string, key: string | number) =>
  typeof key === 'number' ? `${path}[${key}]` : IDENT_RE.test(key) ? `${path}.${key}` : `${path}[${JSON.stringify(key)}]`;

const whole = (v: string, rule: string, harvest = true): Span[] =>
  isRedacted(v) || isTrivialValue(v) ? [] : [{ start: 0, end: v.length, rule, harvest }];

/** Guess the kind of a parsed JSON document. */
export function detectKind(doc: unknown): DocKind {
  if (isObj(doc)) {
    if (isObj(doc.log) && Array.isArray((doc.log as Obj).entries)) return 'har';
    if (Array.isArray(doc.cookies) || Array.isArray(doc.origins)) return 'storage';
    if (typeof doc.type === 'string') return 'trace';
  }
  return 'json';
}

const ACTION_RE = /(?:^|[.\s])(fill|type|presssequentially)\b|^(fill|type)\b/i;
const STEP_TITLE_RE = /^(?:Fill|Type|Press sequentially)\s+"([\s\S]*)"/;

function mentionsPassword(...vals: unknown[]): boolean {
  return vals.some((v) => typeof v === 'string' && PASSWORD_SELECTOR_RE.test(v));
}

/** Fields of a Playwright action whose values are typed into a password-like input. */
function passwordActionFields(o: Obj): Set<string> | null {
  const params = o.params;
  if (!isObj(params)) return null;
  const name = [o.method, o.apiName, o.title].filter((x) => typeof x === 'string').join(' ');
  if (!ACTION_RE.test(name)) return null;
  if (!mentionsPassword(params.selector, params.locator, o.subtitle)) return null;
  return new Set(['value', 'text']);
}

function isPasswordInputNode(arr: unknown[]): Obj | null {
  if (typeof arr[0] !== 'string' || !isObj(arr[1])) return null;
  const tag = arr[0].toUpperCase();
  if (tag !== 'INPUT') return null;
  const attrs = arr[1];
  const type = attrs.type;
  if (typeof type === 'string' && type.toLowerCase() === 'password') return attrs;
  return null;
}

export class JsonScrubber {
  readonly hits: JsonHit[] = [];
  constructor(
    private readonly det: Detector,
    private readonly kind: DocKind,
  ) {}

  /** Returns the (possibly) rewritten document. Hits are collected in `this.hits`. */
  run(doc: unknown, root = '$'): unknown {
    return this.walk(doc, root, false, null);
  }

  private str(v: string, path: string, extra: Span[]): string {
    const hits = this.det.scan(v, extra);
    if (hits.length === 0) return v;
    for (const h of hits) this.hits.push({ path, rule: h.rule, value: h.value, harvest: h.harvest });
    return applyHits(v, hits);
  }

  private walk(node: unknown, path: string, cookieEntry: boolean, forced: Set<string> | null): unknown {
    if (typeof node === 'string') return this.str(node, path, []);
    if (Array.isArray(node)) {
      const pwAttrs = isPasswordInputNode(node);
      let changed = false;
      const out = node.map((el, i) => {
        let r: unknown;
        if (pwAttrs && i === 1) r = this.walkPasswordAttrs(pwAttrs, childPath(path, 1));
        else r = this.walk(el, childPath(path, i), false, null);
        if (r !== el) changed = true;
        return r;
      });
      return changed ? out : node;
    }
    if (!isObj(node)) return node;
    return this.walkObject(node, path, cookieEntry, forced);
  }

  private walkPasswordAttrs(attrs: Obj, path: string): unknown {
    let changed = false;
    const out: Obj = {};
    for (const [k, v] of Object.entries(attrs)) {
      let r: unknown = v;
      const p = childPath(path, k);
      if (typeof v === 'string' && (k === '__playwright_value_' || k === 'value')) {
        r = this.str(v, p, whole(v, 'password-input'));
      } else {
        r = this.walk(v, p, false, null);
      }
      if (r !== v) changed = true;
      out[k] = r;
    }
    return changed ? out : attrs;
  }

  private walkObject(o: Obj, path: string, cookieEntry: boolean, forced: Set<string> | null): unknown {
    const det = this.det;
    const pairName = typeof o.name === 'string' && typeof o.value === 'string' ? o.name : null;
    const pwFields = passwordActionFields(o);

    // Step titles such as: Fill "hunter2" (with subtitle getByLabel('Password'))
    let titleSpans: Span[] = [];
    if (typeof o.title === 'string') {
      const m = STEP_TITLE_RE.exec(o.title);
      const params = isObj(o.params) ? o.params : {};
      if (m && m[1] && mentionsPassword(o.subtitle, params.locator, params.selector)) {
        const start = o.title.indexOf('"') + 1;
        titleSpans = whole(m[1], 'password-fill').map((s) => ({ ...s, start, end: start + m[1].length }));
      }
    }

    let changed = false;
    const out: Obj = {};
    for (const [k, v] of Object.entries(o)) {
      const p = childPath(path, k);
      let r: unknown = v;
      if (typeof v === 'string') {
        let extra: Span[] = [];
        const lk = k.toLowerCase();
        if (forced?.has(k)) {
          extra = whole(v, 'password-fill');
        } else if (k === 'title' && titleSpans.length) {
          extra = titleSpans;
        } else if (pairName !== null && k === 'value') {
          const n = pairName.toLowerCase();
          if (cookieEntry) {
            const sensitive = det.isSensitiveKey(pairName);
            if (this.kind !== 'storage' || sensitive) extra = whole(v, 'cookie', sensitive);
          } else if (n === 'cookie' || n === 'set-cookie') {
            extra = cookieHeaderSpans(v, n === 'set-cookie', det);
          } else if (n === 'authorization' || n === 'proxy-authorization') {
            extra = authorizationSpans(v);
          } else if (det.isSensitiveKey(pairName)) {
            extra = whole(v, this.kind === 'storage' ? 'local-storage' : 'sensitive-key');
          }
        } else if (lk === 'authorization' || lk === 'proxy-authorization') {
          extra = authorizationSpans(v);
        } else if (lk === 'cookie' || lk === 'set-cookie') {
          extra = cookieHeaderSpans(v, lk === 'set-cookie', det);
        } else if (k !== 'name' && det.isSensitiveKey(k)) {
          extra = whole(v, 'sensitive-key');
        }
        r = this.str(v, p, extra);
      } else if (Array.isArray(v) && k.toLowerCase() === 'cookies') {
        let arrChanged = false;
        const arr = v.map((el, i) => {
          const rr = this.walk(el, childPath(p, i), true, null);
          if (rr !== el) arrChanged = true;
          return rr;
        });
        r = arrChanged ? arr : v;
      } else {
        r = this.walk(v, p, false, k === 'params' ? pwFields : null);
      }
      if (r !== v) changed = true;
      out[k] = r;
    }
    return changed ? out : o;
  }
}

export function scrubJson(doc: unknown, det: Detector, kind: DocKind = detectKind(doc)) {
  const s = new JsonScrubber(det, kind);
  const value = s.run(doc);
  return { value, hits: s.hits, changed: value !== doc };
}
