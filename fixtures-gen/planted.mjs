// Obviously fake values planted into the generated fixtures.
// None of these are real credentials. The JWT is built locally from fake
// claims and a fake signature; it does not verify against any key.

const b64url = (s) => Buffer.from(s).toString('base64url');

export const FAKE_JWT = [
  b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })),
  b64url(JSON.stringify({ sub: 'fake-user-0001', name: 'Fake Tester', iss: 'tracescrub-fixtures', iat: 1767225600, note: 'FAKE token for tests' })),
  b64url('FAKE_SIGNATURE_NOT_REAL_tracescrub'),
].join('.');

export const PLANTED = {
  username: 'fake.tester@example.test',
  password: 'tsk_FAKE_Passw0rd_9f3a7c',
  apiKey: 'tsk_FAKE_apikey_5b8e2d41c7a9',
  sessionCookie: 'tsk_FAKE_session_c0ffee1234',
  localToken: 'tsk_FAKE_localtoken_7e1d9a',
  jwt: FAKE_JWT,
};
