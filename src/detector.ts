import {
  builtinTextRules,
  defaultIsSensitiveKey,
  isRedacted,
  regexSpans,
  type RuleContext,
  type Span,
  type TextRule,
} from './rules.js';

export interface KnownValue {
  value: string;
  rule: string;
}

export interface CustomPattern {
  name: string;
  regex: string;
  flags?: string;
  group?: number;
}

export interface DetectorOptions {
  /** Literal values that must be redacted wherever they appear (env values, harvested secrets). */
  knownValues?: KnownValue[];
  /** Extra regexes from the config file. */
  patterns?: CustomPattern[];
  /** Extra key names treated as sensitive (exact match, case-insensitive). */
  sensitiveKeys?: string[];
  /** Values (literal, or /regex/flags) that are never reported. */
  allowlist?: string[];
  /** Built-in rule names to switch off. */
  disableRules?: string[];
  /** Minimum length for known values. Default 6. */
  minKnownLength?: number;
}

/** A detected secret inside one string. `value` is kept in memory only, never printed. */
export interface Hit {
  start: number;
  end: number;
  rule: string;
  value: string;
  harvest: boolean;
}

export class Detector implements RuleContext {
  private readonly rules: TextRule[];
  private readonly extraKeys: Set<string>;
  private readonly allowLiterals = new Set<string>();
  private readonly allowRegexes: RegExp[] = [];
  private readonly known = new Map<string, string>();
  readonly minKnownLength: number;

  constructor(opts: DetectorOptions = {}) {
    this.minKnownLength = opts.minKnownLength ?? 6;
    const disabled = new Set(opts.disableRules ?? []);
    this.rules = builtinTextRules().filter((r) => !disabled.has(r.name));
    for (const p of opts.patterns ?? []) {
      const re = new RegExp(p.regex, p.flags ?? '');
      const name = `config:${p.name}`;
      const group = p.group ?? 0;
      this.rules.push({ name, find: (text) => regexSpans(re, text, name, group, true) });
    }
    this.extraKeys = new Set((opts.sensitiveKeys ?? []).map((k) => k.toLowerCase()));
    for (const a of opts.allowlist ?? []) {
      const m = /^\/(.+)\/([a-z]*)$/s.exec(a);
      if (m) this.allowRegexes.push(new RegExp(m[1], m[2].replace(/[gy]/g, '')));
      else this.allowLiterals.add(a);
    }
    for (const k of opts.knownValues ?? []) this.addKnown(k.value, k.rule);
  }

  isSensitiveKey(name: string): boolean {
    return defaultIsSensitiveKey(name, this.extraKeys);
  }

  isAllowed(value: string): boolean {
    if (this.allowLiterals.has(value)) return true;
    return this.allowRegexes.some((r) => r.test(value));
  }

  /** "Bearer <token>" -> just the token, so the scheme stays readable elsewhere. */
  private static normalizeKnown(value: string): string {
    return value.trim().replace(/^(?:Bearer|Basic|Token)\s+/i, '');
  }

  /** True when `value` would be dropped by {@link addKnown} only because it is shorter than `minKnownLength`. */
  isTooShortToKnow(value: string): boolean {
    if (typeof value !== 'string') return false;
    const v = Detector.normalizeKnown(value);
    return v.length > 0 && v.length < this.minKnownLength && !isRedacted(v) && !this.isAllowed(v);
  }

  /** Register a literal secret. Returns false when it was ignored (too short, allowlisted, duplicate). */
  addKnown(value: string, rule: string): boolean {
    if (typeof value !== 'string') return false;
    const v = Detector.normalizeKnown(value);
    if (v.length < this.minKnownLength || isRedacted(v) || this.isAllowed(v)) return false;
    if (this.known.has(v)) return false;
    this.known.set(v, rule);
    return true;
  }

  get knownCount(): number {
    return this.known.size;
  }

  /** Find secrets in a free-form string. `extra` spans come from structural rules. */
  scan(text: string, extra: Span[] = []): Hit[] {
    if (!text) return [];
    const spans: Span[] = [...extra];
    for (const rule of this.rules) spans.push(...rule.find(text, this));
    for (const [value, rule] of this.known) {
      let i = text.indexOf(value);
      while (i !== -1) {
        spans.push({ start: i, end: i + value.length, rule });
        i = text.indexOf(value, i + value.length);
      }
    }
    return this.merge(text, spans);
  }

  private merge(text: string, spans: Span[]): Hit[] {
    const sorted = spans
      .map((s, i) => ({ ...s, i }))
      .filter((s) => s.end > s.start)
      .sort((a, b) => a.start - b.start || b.end - a.end || a.i - b.i);
    const out: Hit[] = [];
    for (const s of sorted) {
      const last = out[out.length - 1];
      if (last && s.start < last.end) {
        if (s.end > last.end) {
          last.end = s.end;
          last.value = text.slice(last.start, last.end);
        }
        last.harvest = last.harvest || Boolean(s.harvest);
        continue;
      }
      out.push({ start: s.start, end: s.end, rule: s.rule, value: text.slice(s.start, s.end), harvest: Boolean(s.harvest) });
    }
    return out.filter((h) => !this.isAllowed(h.value) && !this.isAllowed(h.value.trim()) && !isRedacted(h.value));
  }
}

export function redactionTag(rule: string): string {
  return `[REDACTED:${rule}]`;
}

/** Replace hits (as returned by Detector.scan) with redaction tags. */
export function applyHits(text: string, hits: Hit[]): string {
  if (hits.length === 0) return text;
  let out = '';
  let pos = 0;
  for (const h of [...hits].sort((a, b) => a.start - b.start)) {
    out += text.slice(pos, h.start) + redactionTag(h.rule);
    pos = h.end;
  }
  return out + text.slice(pos);
}
