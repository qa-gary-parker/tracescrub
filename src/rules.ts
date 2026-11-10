/**
 * Built-in detection rules.
 *
 * Every rule finds spans inside a single string. A span marks the exact
 * characters that should be redacted (for example only the token after
 * "Bearer ", not the scheme itself).
 */

export interface Span {
  start: number;
  end: number;
  rule: string;
  /** When true, the matched value is remembered and redacted everywhere else too. */
  harvest?: boolean;
}

export interface RuleContext {
  isSensitiveKey(name: string): boolean;
}

export interface TextRule {
  name: string;
  find(text: string, ctx: RuleContext): Span[];
}

const REDACTED_MARK = '[REDACTED:';

export function isRedacted(value: string): boolean {
  return value.includes(REDACTED_MARK);
}

/** Key names that look sensitive. Matched case-insensitively against the whole key. */
export const SENSITIVE_KEY_RE =
  /pass(?:word|wd|phrase|code)?(?![a-z])|pwd|secret|token|api[-_]?key|apikey|auth(?!or)|session|sessid|(?:^|[^a-z])sid(?:$|[^a-z])|credential|private[-_]?key|access[-_]?key|jwt|bearer|csrf|xsrf|(?:^|[^a-z])otp(?:$|[^a-z])/i;

/** Key names that contain a sensitive word but describe metadata rather than a secret. */
export const NON_SECRET_KEY_RE =
  /(?:type|kind|expires?|expiry|expires_?in|expires_?at|length|count|size|url|uri|path|hint|label|placeholder|name|required|strength|policy|enabled)$/i;

export function defaultIsSensitiveKey(name: string, extra: ReadonlySet<string> = new Set()): boolean {
  const n = name.trim().toLowerCase();
  if (!n) return false;
  if (extra.has(n)) return true;
  if (NON_SECRET_KEY_RE.test(n)) return false;
  return SENSITIVE_KEY_RE.test(n);
}

/** Values that are never worth redacting even under a sensitive key. */
export function isTrivialValue(v: string): boolean {
  const t = v.trim().toLowerCase();
  return t === '' || t === 'true' || t === 'false' || t === 'null' || t === 'undefined' || t === 'none';
}

/** Run a regex globally and return a span for capture group `group` (0 = whole match). */
export function regexSpans(re: RegExp, text: string, rule: string, group = 0, harvest = false): Span[] {
  let flags = re.flags;
  if (!flags.includes('g')) flags += 'g';
  if (!flags.includes('d')) flags += 'd';
  const r = new RegExp(re.source, flags);
  const out: Span[] = [];
  let m: RegExpExecArray | null;
  while ((m = r.exec(text)) !== null) {
    if (m[0].length === 0) {
      r.lastIndex++;
      continue;
    }
    const idx = m.indices?.[group];
    if (!idx) continue;
    const [start, end] = idx;
    if (end <= start) continue;
    if (isRedacted(text.slice(start, end))) continue;
    out.push({ start, end, rule, harvest });
  }
  return out;
}

function patternRule(name: string, re: RegExp, group = 0): TextRule {
  return { name, find: (text) => regexSpans(re, text, name, group) };
}

/**
 * Cookie header values: every cookie value in a `Cookie` header, and the first
 * name=value pair of each `Set-Cookie` line. Attributes such as Path stay.
 */
export function cookieHeaderSpans(value: string, isSetCookie: boolean, ctx: RuleContext, base = 0): Span[] {
  const spans: Span[] = [];
  let lineStart = 0;
  for (const line of value.split('\n')) {
    const pairs = isSetCookie ? [line.split(';')[0]] : line.split(';');
    let offset = lineStart;
    for (const pair of pairs) {
      const eq = pair.indexOf('=');
      if (eq > 0) {
        const name = pair.slice(0, eq).trim();
        let vStart = eq + 1;
        let vEnd = pair.length;
        while (vStart < vEnd && /\s/.test(pair[vStart])) vStart++;
        while (vEnd > vStart && /\s/.test(pair[vEnd - 1])) vEnd--;
        const v = pair.slice(vStart, vEnd);
        if (v && !isRedacted(v)) {
          spans.push({
            start: base + offset + vStart,
            end: base + offset + vEnd,
            rule: 'cookie',
            harvest: ctx.isSensitiveKey(name),
          });
        }
      }
      offset += pair.length + 1;
    }
    lineStart += line.length + 1;
  }
  return spans;
}

/** Authorization header value: redact the credential after the scheme, or the whole value. */
export function authorizationSpans(value: string): Span[] {
  if (!value.trim() || isRedacted(value)) return [];
  const m = /^\s*[A-Za-z][A-Za-z0-9_-]*\s+(\S[\s\S]*)$/.exec(value);
  if (m) {
    return [{ start: value.length - m[1].length, end: value.length, rule: 'authorization', harvest: true }];
  }
  return [{ start: 0, end: value.length, rule: 'authorization', harvest: true }];
}

const KEY_CHARS = '[A-Za-z0-9_.\\-]';

export function builtinTextRules(): TextRule[] {
  return [
    patternRule(
      'private-key',
      /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/,
    ),
    patternRule('jwt', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/),
    patternRule('aws-access-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/),
    patternRule('github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/),
    patternRule('slack-token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/),
    patternRule('stripe-key', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/),
    patternRule('anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{20,}/),
    patternRule('openai-key', /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/),
    patternRule('authorization', /\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{8,})/, 1),
    {
      // "Cookie: a=b; c=d" or "Set-Cookie: a=b; Path=/" inside free text (raw HTTP dumps, logs).
      name: 'cookie',
      find(text, ctx) {
        const re = /(?:^|\n)[ \t]*(set-)?cookie[ \t]*:[ \t]*([^\r\n]*)/dgi;
        const out: Span[] = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          const idx = m.indices?.[2];
          if (!idx) continue;
          out.push(...cookieHeaderSpans(m[2], Boolean(m[1]), ctx, idx[0]));
        }
        return out;
      },
    },
    {
      // "password": "x", password: 'x', password = "x" (JSON inside strings, JS source, YAML-ish text)
      name: 'sensitive-key',
      find(text, ctx) {
        const re = new RegExp(
          `(["']?)(${KEY_CHARS}{1,64})\\1[ \\t]*[:=][ \\t]*(["'])((?:(?!\\3)[^\\\\\\r\\n]|\\\\.)*)\\3`,
          'dg',
        );
        const out: Span[] = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          const idx = m.indices?.[4];
          if (!idx || idx[1] <= idx[0]) continue;
          if (!ctx.isSensitiveKey(m[2])) continue;
          const v = m[4];
          if (isRedacted(v) || isTrivialValue(v)) continue;
          out.push({ start: idx[0], end: idx[1], rule: 'sensitive-key', harvest: true });
        }
        return out;
      },
    },
    {
      // password=x&token=y in form bodies and query strings
      name: 'form-field',
      find(text, ctx) {
        const re = /(?:^|[?&;\s])([A-Za-z0-9_.\-[\]%]{1,64})=([^&\s#"'<>;]+)/dg;
        const out: Span[] = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          const idx = m.indices?.[2];
          if (!idx) continue;
          re.lastIndex = idx[1];
          let name = m[1];
          try {
            name = decodeURIComponent(name);
          } catch {
            /* keep the raw name */
          }
          if (!ctx.isSensitiveKey(name.replace(/[[\]]/g, '_'))) continue;
          const v = m[2];
          if (isRedacted(v) || isTrivialValue(v)) continue;
          out.push({ start: idx[0], end: idx[1], rule: 'form-field', harvest: true });
        }
        return out;
      },
    },
  ];
}

/** Selector or locator text that points at a password-like input. */
export const PASSWORD_SELECTOR_RE =
  /pass(?:word|wd|phrase|code)?(?![a-z])|pwd|secret|(?:^|[^a-z])pin(?:$|[^a-z])|(?:^|[^a-z])otp(?:$|[^a-z])|cvv|cvc|api[-_ ]?key/i;
