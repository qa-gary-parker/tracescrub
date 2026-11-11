import { describe, expect, it } from 'vitest';
import { Detector } from '../src/detector.js';
import { detectKind, scrubJson } from '../src/structural.js';
import { FAKE_JWT } from './helpers.js';

const det = new Detector();
const run = (doc: unknown, d = det) => scrubJson(doc, d);

describe('HAR / network entries', () => {
  const har = {
    log: {
      entries: [
        {
          request: {
            url: 'https://app.test/api?api_key=abcdef123456',
            headers: [
              { name: 'Authorization', value: `Bearer ${FAKE_JWT}` },
              { name: 'Cookie', value: 'session=abc123456; theme=dark' },
              { name: 'X-API-Key', value: 'tsk_FAKE_key_000000' },
              { name: 'Accept', value: 'application/json' },
            ],
            cookies: [{ name: 'theme', value: 'dark' }],
            postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'password', value: 'hunter2hunter2' }] },
          },
          response: { headers: [{ name: 'Set-Cookie', value: 'session=abc123456; Path=/; HttpOnly' }] },
        },
      ],
    },
  };

  it('detects the kind', () => expect(detectKind(har)).toBe('har'));

  it('redacts headers, cookies, params and query strings', () => {
    const { value, hits } = run(har);
    const req = (value as typeof har).log.entries[0].request;
    expect(req.headers[0].value).toBe('Bearer [REDACTED:authorization]');
    expect(req.headers[1].value).toBe('session=[REDACTED:cookie]; theme=[REDACTED:cookie]');
    expect(req.headers[2].value).toBe('[REDACTED:sensitive-key]');
    expect(req.headers[3].value).toBe('application/json');
    expect(req.cookies[0].value).toBe('[REDACTED:cookie]');
    expect(req.postData.params[0].value).toBe('[REDACTED:sensitive-key]');
    expect(req.url).toBe('https://app.test/api?api_key=[REDACTED:form-field]');
    const res = (value as typeof har).log.entries[0].response;
    expect(res.headers[0].value).toBe('session=[REDACTED:cookie]; Path=/; HttpOnly');
    expect(hits.find((h) => h.rule === 'authorization')?.path).toBe('$.log.entries[0].request.headers[0].value');
  });

  it('does not mutate the input', () => {
    const copy = JSON.parse(JSON.stringify(har));
    run(har);
    expect(har).toEqual(copy);
  });
});

describe('storageState', () => {
  const state = {
    cookies: [
      { name: 'sessionid', value: 'abcdef123456', domain: 'x.test' },
      { name: 'theme', value: 'dark-mode-on', domain: 'x.test' },
      { name: 'prefs', value: FAKE_JWT, domain: 'x.test' },
    ],
    origins: [
      {
        origin: 'https://x.test',
        localStorage: [
          { name: 'auth_token', value: 'opaque-token-123' },
          { name: 'theme', value: 'dark' },
          { name: 'user', value: JSON.stringify({ id: 1, accessToken: 'abc-def-ghi' }) },
        ],
      },
    ],
  };

  it('detects the kind', () => expect(detectKind(state)).toBe('storage'));

  it('redacts only sensitive or pattern-matching cookies and localStorage values', () => {
    const v = run(state).value as typeof state;
    expect(v.cookies[0].value).toBe('[REDACTED:cookie]');
    expect(v.cookies[1].value).toBe('dark-mode-on');
    expect(v.cookies[2].value).toBe('[REDACTED:jwt]');
    expect(v.origins[0].localStorage[0].value).toBe('[REDACTED:local-storage]');
    expect(v.origins[0].localStorage[1].value).toBe('dark');
    expect(v.origins[0].localStorage[2].value).toBe('{"id":1,"accessToken":"[REDACTED:sensitive-key]"}');
  });
});

describe('Playwright-aware rules', () => {
  it('redacts fill values on password-like selectors only', () => {
    const pw = run({ type: 'before', method: 'fill', params: { selector: 'internal:label="Password"i', value: 'hunter2' } });
    expect((pw.value as { params: { value: string } }).params.value).toBe('[REDACTED:password-fill]');
    const email = run({ type: 'before', method: 'fill', params: { selector: '#email', value: 'bob@example.test' } });
    expect(email.changed).toBe(false);
  });

  it('treats camelCase selectors such as #passwordConfirm as password inputs', () => {
    const r = run({ type: 'before', method: 'fill', params: { selector: '#passwordConfirm', value: 'hunter2' } });
    expect((r.value as { params: { value: string } }).params.value).toBe('[REDACTED:password-fill]');
    const other = run({ type: 'before', method: 'fill', params: { selector: '#passwordlessEmail', value: 'bob@example.test' } });
    expect(other.changed).toBe(false);
  });

  it('redacts type / pressSequentially text on password inputs', () => {
    const r = run({ type: 'before', apiName: 'locator.pressSequentially', params: { selector: 'input[name=pwd]', text: 'hunter2' } });
    expect((r.value as { params: { text: string } }).params.text).toBe('[REDACTED:password-fill]');
  });

  it('redacts test step titles that echo a password', () => {
    const r = run({
      type: 'before',
      method: 'pw:api',
      title: 'Fill "hunter2"',
      subtitle: "getByLabel('Password')",
      params: { locator: "getByLabel('Password')", value: 'hunter2' },
    });
    const v = r.value as { title: string; params: { value: string } };
    expect(v.title).toBe('Fill "[REDACTED:password-fill]"');
    expect(v.params.value).toBe('[REDACTED:password-fill]');
  });

  it('redacts password input values in DOM snapshots', () => {
    const snap = {
      type: 'frame-snapshot',
      snapshot: {
        html: [
          'HTML',
          {},
          ['INPUT', { __playwright_value_: 'bob@example.test', type: 'email' }],
          ['INPUT', { __playwright_value_: 'hunter2', type: 'password', value: 'hunter2' }],
        ],
      },
    };
    const r = run(snap);
    const html = (r.value as typeof snap).snapshot.html as unknown[];
    expect((html[2] as unknown[])[1]).toEqual({ __playwright_value_: 'bob@example.test', type: 'email' });
    expect((html[3] as unknown[])[1]).toEqual({
      __playwright_value_: '[REDACTED:password-input]',
      type: 'password',
      value: '[REDACTED:password-input]',
    });
    expect(r.hits.every((h) => h.harvest)).toBe(true);
  });
});
