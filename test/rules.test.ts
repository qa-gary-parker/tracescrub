import { describe, expect, it } from 'vitest';
import { applyHits, Detector } from '../src/detector.js';
import { mask } from '../src/mask.js';
import { defaultIsSensitiveKey } from '../src/rules.js';
import { FAKE_JWT, FAKE_KEYS } from './helpers.js';

const det = new Detector();
const rulesIn = (text: string, d = det) => d.scan(text).map((h) => h.rule);
const scrub = (text: string, d = det) => applyHits(text, d.scan(text));

describe('built-in patterns', () => {
  it('finds a JWT', () => {
    expect(rulesIn(`token is ${FAKE_JWT} ok`)).toEqual(['jwt']);
    expect(scrub(`x ${FAKE_JWT} y`)).toBe('x [REDACTED:jwt] y');
  });

  it('redacts only the credential of Bearer and Basic values', () => {
    expect(scrub('Authorization: Bearer abcdefgh12345678')).toBe('Authorization: Bearer [REDACTED:authorization]');
    expect(scrub('Basic ZmFrZTpmYWtlcGFzcw==')).toBe('Basic [REDACTED:authorization]');
  });

  it('redacts Cookie and Set-Cookie header values in free text', () => {
    expect(scrub('Cookie: sid=abc123; theme=dark')).toBe('Cookie: sid=[REDACTED:cookie]; theme=[REDACTED:cookie]');
    expect(scrub('Set-Cookie: session=abc123; Path=/; HttpOnly')).toBe(
      'Set-Cookie: session=[REDACTED:cookie]; Path=/; HttpOnly',
    );
  });

  it('redacts sensitive keys in embedded JSON and JS', () => {
    expect(scrub('{"user":"bob","password":"hunter2hunter2"}')).toBe('{"user":"bob","password":"[REDACTED:sensitive-key]"}');
    expect(scrub(`headers: { 'X-API-Key': 'abc-123-def' }`)).toBe(`headers: { 'X-API-Key': '[REDACTED:sensitive-key]' }`);
    expect(scrub('{"client_secret": "s3cr3t-value"}')).toContain('[REDACTED:sensitive-key]');
  });

  it('ignores metadata keys and trivial values', () => {
    expect(rulesIn('{"token_type":"Bearer","passwordRequired":"true","name":"password"}')).toEqual([]);
    expect(rulesIn('{"password":""}')).toEqual([]);
    expect(rulesIn('{"author":"Someone"}')).toEqual([]);
  });

  it('redacts form fields and query parameters', () => {
    expect(scrub('user=bob&password=hunter2&remember=1')).toBe('user=bob&password=[REDACTED:form-field]&remember=1');
    expect(scrub('https://x.test/cb?code=1&access_token=abc.def&x=2')).toBe(
      'https://x.test/cb?code=1&access_token=[REDACTED:form-field]&x=2',
    );
  });

  it.each([
    ['aws-access-key', FAKE_KEYS.aws],
    ['github-token', FAKE_KEYS.github],
    ['github-token', FAKE_KEYS.githubPat],
    ['slack-token', FAKE_KEYS.slack],
    ['stripe-key', FAKE_KEYS.stripe],
    ['openai-key', FAKE_KEYS.openai],
    ['anthropic-key', FAKE_KEYS.anthropic],
    ['private-key', FAKE_KEYS.pem],
  ])('finds %s', (rule, value) => {
    const hits = det.scan(`value: ${value} end`);
    expect(hits.map((h) => h.rule)).toEqual([rule]);
    expect(hits[0].value).toBe(value);
  });

  it('does not flag ordinary text', () => {
    expect(rulesIn('The quick brown fox jumps over the lazy dog. Passed 12 tests in 3s.')).toEqual([]);
    expect(rulesIn('<input type="password" name="password" id="password">')).toEqual([]);
  });

  it('does not re-flag already redacted text', () => {
    const once = scrub(`Bearer ${FAKE_JWT} {"password":"hunter2x"} sid=abcdef`);
    expect(det.scan(once)).toEqual([]);
  });
});

describe('known values', () => {
  it('redacts known values and ignores short ones', () => {
    const d = new Detector({
      knownValues: [
        { value: 'correct-horse-battery', rule: 'env:TEST_PASSWORD' },
        { value: 'abc', rule: 'env:SHORT' },
      ],
    });
    expect(d.knownCount).toBe(1);
    expect(scrub('typed correct-horse-battery and abc', d)).toBe('typed [REDACTED:env:TEST_PASSWORD] and abc');
  });

  it('respects a custom minimum length', () => {
    const d = new Detector({ minKnownLength: 3, knownValues: [{ value: 'abc', rule: 'env:X' }] });
    expect(scrub('abc', d)).toBe('[REDACTED:env:X]');
  });
});

describe('config options', () => {
  it('adds custom patterns', () => {
    const d = new Detector({ patterns: [{ name: 'internal', regex: 'itk_[a-z0-9]{8}' }] });
    expect(scrub('key itk_abcd1234 here', d)).toBe('key [REDACTED:config:internal] here');
  });

  it('adds sensitive key names', () => {
    const d = new Detector({ sensitiveKeys: ['X-Tenant-Seed'] });
    expect(d.isSensitiveKey('x-tenant-seed')).toBe(true);
    expect(scrub('{"x-tenant-seed":"abcdefgh"}', d)).toContain('[REDACTED:sensitive-key]');
  });

  it('honours the allowlist (literal and regex)', () => {
    const d = new Detector({ allowlist: ['hunter2hunter2', '/^example-/'] });
    expect(rulesIn('{"password":"hunter2hunter2"}', d)).toEqual([]);
    expect(rulesIn('{"token":"example-token-value"}', d)).toEqual([]);
    expect(rulesIn('{"token":"real-token-value"}', d)).toEqual(['sensitive-key']);
  });

  it('can disable a built-in rule', () => {
    const d = new Detector({ disableRules: ['form-field'] });
    expect(rulesIn('password=hunter2', d)).toEqual([]);
  });
});

describe('sensitive key names', () => {
  it.each(['password', 'Passwd', 'user_pass', 'api_key', 'X-API-Key', 'apikey', 'access_token', 'Authorization', 'sessionid', 'client_secret', 'csrftoken', 'sid'])(
    '%s is sensitive',
    (k) => expect(defaultIsSensitiveKey(k)).toBe(true),
  );
  it.each(['passed', 'author', 'token_type', 'passwordHint', 'username', 'theme', 'consider', 'expires'])('%s is not sensitive', (k) =>
    expect(defaultIsSensitiveKey(k)).toBe(false),
  );
});

describe('mask', () => {
  it('never returns the full value', () => {
    for (const v of ['abcdef', 'hunter2hunter2', FAKE_JWT, FAKE_KEYS.pem]) {
      const m = mask(v);
      expect(m).not.toContain(v);
      expect(m).toMatch(/\*{6} \(\d+ chars\)$/);
    }
    expect(mask('abcdefghijklmnopqrstuvwx')).toBe('abcd****** (24 chars)');
    expect(mask('short')).toBe('****** (5 chars)');
  });
});
