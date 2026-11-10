import JSZip from 'jszip';
import path from 'node:path';
import { main } from '../src/main.js';

export const FIXTURES = path.join(import.meta.dirname, 'fixtures');

const b64url = (s: string) => Buffer.from(s).toString('base64url');

/** Same fake JWT as fixtures-gen/planted.mjs. */
export const FAKE_JWT = [
  b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })),
  b64url(
    JSON.stringify({
      sub: 'fake-user-0001',
      name: 'Fake Tester',
      iss: 'tracescrub-fixtures',
      iat: 1767225600,
      note: 'FAKE token for tests',
    }),
  ),
  b64url('FAKE_SIGNATURE_NOT_REAL_tracescrub'),
].join('.');

/** Values planted in the committed fixtures (see fixtures-gen/planted.mjs). All fake. */
export const PLANTED = {
  password: 'tsk_FAKE_Passw0rd_9f3a7c',
  apiKey: 'tsk_FAKE_apikey_5b8e2d41c7a9',
  sessionCookie: 'tsk_FAKE_session_c0ffee1234',
  localToken: 'tsk_FAKE_localtoken_7e1d9a',
  jwt: FAKE_JWT,
};
export const PLANTED_VALUES = Object.values(PLANTED);

/** Fake key-shaped strings, assembled at runtime so no key-like literal sits in the source. */
export const FAKE_KEYS = {
  aws: 'AKIA' + 'FAKEFAKEFAKEFAKE',
  github: 'ghp' + '_' + 'FAKE'.repeat(9),
  githubPat: 'github' + '_pat_' + 'FAKE0'.repeat(6),
  slack: 'xox' + 'b-' + '000000000000-FAKEFAKEFAKE',
  stripe: 'sk' + '_test_' + 'FAKE'.repeat(6),
  openai: 'sk' + '-proj-' + 'FAKE'.repeat(8),
  anthropic: 'sk' + '-ant-' + 'api03-' + 'FAKE'.repeat(8),
  pem: ['-----BEGIN ' + 'PRIVATE KEY-----', 'FAKEFAKEFAKEFAKEFAKE', 'NOTAREALKEY', '-----END ' + 'PRIVATE KEY-----'].join('\n'),
};

export async function run(argv: string[], env: NodeJS.ProcessEnv = {}) {
  let stdout = '';
  let stderr = '';
  const code = await main(argv, {
    out: (t) => {
      stdout += t.endsWith('\n') ? t : t + '\n';
    },
    err: (t) => {
      stderr += t.endsWith('\n') ? t : t + '\n';
    },
    env,
    cwd: FIXTURES,
  });
  return { code, stdout, stderr };
}

/** Recursively collect every text payload in a buffer: zip entries, the report's embedded zip, plain text. */
export async function allText(name: string, buf: Uint8Array): Promise<string[]> {
  if (name.endsWith('.zip')) {
    const zip = await JSZip.loadAsync(buf);
    const out: string[] = [];
    for (const f of Object.values(zip.files)) {
      if (f.dir) continue;
      out.push(...(await allText(f.name, await f.async('uint8array'))));
    }
    return out;
  }
  const text = Buffer.from(buf).toString('utf8');
  const m = /data:application\/zip;base64,([A-Za-z0-9+/=]+)/.exec(text);
  if (m) return [text, ...(await allText('embedded.zip', Buffer.from(m[1], 'base64')))];
  return [text];
}
