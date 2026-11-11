import { test, expect } from '@playwright/test';
import path from 'node:path';
// @ts-ignore plain ESM helper shared with the generator script
import { PLANTED } from '../planted.mjs';

const ORIGIN = 'https://app.tracescrub.test';

const LOGIN_HTML = `<!doctype html>
<html><head><title>Fake login</title></head>
<body>
  <h1>Sign in</h1>
  <form id="login">
    <label>Email <input id="email" name="email" type="email"></label>
    <label>Password <input id="password" name="password" type="password"></label>
    <button type="submit">Sign in</button>
  </form>
  <p id="status"></p>
  <script>
    document.getElementById('login').addEventListener('submit', async (e) => {
      e.preventDefault();
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ${PLANTED.jwt}',
          'X-API-Key': '${PLANTED.apiKey}',
        },
        body: JSON.stringify({
          email: document.getElementById('email').value,
          password: document.getElementById('password').value,
        }),
      });
      const data = await res.json();
      localStorage.setItem('auth_token', '${PLANTED.localToken}');
      localStorage.setItem('theme', 'dark');
      document.getElementById('status').textContent = 'Welcome ' + data.name;
    });
  </script>
</body></html>`;

test('fake login leaks secrets into artifacts', async ({ page, context }) => {
  await page.route(`${ORIGIN}/**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/login') {
      return route.fulfill({ status: 200, contentType: 'text/html', body: LOGIN_HTML });
    }
    if (url.pathname === '/api/login') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Set-Cookie': `session=${PLANTED.sessionCookie}; Path=/; HttpOnly; Secure` },
        body: JSON.stringify({ name: 'Fake Tester', access_token: PLANTED.jwt }),
      });
    }
    return route.fulfill({ status: 404, body: 'not found' });
  });

  await context.addCookies([
    { name: 'session', value: PLANTED.sessionCookie, domain: 'app.tracescrub.test', path: '/', httpOnly: true, secure: true },
    { name: 'locale', value: 'en-GB', domain: 'app.tracescrub.test', path: '/' },
  ]);

  await page.goto(`${ORIGIN}/login`);
  await page.getByLabel('Email').fill(PLANTED.username);
  await page.getByLabel('Password').fill(PLANTED.password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.locator('#status')).toHaveText('Welcome Fake Tester');

  await context.storageState({ path: path.join(import.meta.dirname, '..', '.out', 'storageState.json') });
});
