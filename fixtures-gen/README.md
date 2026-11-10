# fixtures-gen

A tiny Playwright project that produces the committed fixtures in `test/fixtures/`.

It serves a fake login page through `page.route` (no network, no real server), then:

- fills the password field with a planted fake password,
- sends a `fetch` with `Authorization: Bearer <fake JWT>` and an `X-API-Key` header,
- receives a `Set-Cookie` session cookie and an `access_token` in the JSON body,
- stores a token in `localStorage`, adds a session cookie,
- saves `storageState`, and records a trace (`trace: 'on'`), a HAR (`recordHar`) and an HTML report.

All planted values live in `planted.mjs`. They are obviously fake (`tsk_FAKE_...`), and the JWT is
assembled locally from fake claims with a fake signature.

## Regenerate

```sh
npx playwright install chromium
npm run fixtures:gen
```

`generate.mjs` copies the artifacts into `test/fixtures/` and makes two small changes so the
fixtures are portable and small:

- absolute local paths in stack traces are replaced with `/work/tracescrub`;
- the HTML report's `index.html` is trimmed to just the embedded results zip
  (`<template id="playwrightReportBase64">`). The report app bundle is about 500 KB of JavaScript
  and holds no test data. `data/*.zip` is the real trace.

Everything else is unmodified Playwright output.
