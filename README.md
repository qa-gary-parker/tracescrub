# tracescrub

Scrub secrets from Playwright traces, HTML reports, HAR files and `storageState` JSON **before** they
become CI artifacts.

> Status: MVP / prototype. On npm as [`pw-tracescrub`](https://www.npmjs.com/package/pw-tracescrub); the CLI command is `tracescrub`.

Overview and FAQ: [garyparker.dev/projects/tracescrub](https://garyparker.dev/projects/tracescrub)

## The problem

Playwright artifacts are excellent for debugging, and that is exactly why they leak:

- `trace.zip` records every action with its parameters, so `fill(password)` stores the password in
  plain text. It also stores DOM snapshots (including the value of `<input type=password>`), every
  request and response header (`Authorization`, `Cookie`, `Set-Cookie`, API keys) and response bodies.
- The HTML report (`playwright-report/`) embeds those same trace zips under `data/`, and its
  `index.html` embeds test step titles such as `Fill "hunter2"`.
- `recordHar` files contain full headers, cookies and bodies.
- `storageState` files contain session cookies and `localStorage` tokens.

These files are uploaded with `actions/upload-artifact`, shared in bug reports, and increasingly read by
AI agents and MCP tools. Anyone who can download the artifact gets the test account's credentials.
See [microsoft/playwright#38673](https://github.com/microsoft/playwright/issues/38673).

`tracescrub` finds those secrets, reports them with a masked preview, and rewrites the files with
`[REDACTED:<rule>]` in their place, while keeping zips valid so the trace still opens in the trace viewer.

## What it scans

| Input | How |
| --- | --- |
| `trace.zip` | Every `*.trace` / `*.network` NDJSON line is parsed and walked as JSON; text resources under `resources/` (HTML, JSON, JS, CSS...) are scanned as text. Images are skipped. |
| HTML report dir | `data/*.zip` as traces, plus the zip embedded in `index.html` (test results and step titles). |
| `*.har` | Headers, cookies, query strings, form params, post bodies and text response bodies. |
| `storageState` JSON | Cookies and `localStorage` entries with sensitive names, or values that match a pattern. |
| Other `*.json`, `*.md`, `*.txt`, `*.log` | Patterns and known values. |

Directories are walked recursively (`node_modules` and `.git` are skipped).

### Detection

1. **Known values.** Values of the environment variables you name (`--env TEST_PASSWORD,API_TOKEN`) and
   every value in a dotenv file (`--env-file .env.test`). Values shorter than 6 characters
   (`minKnownLength`) are ignored, with a warning.
2. **Built-in patterns.** JWTs; `Authorization: Bearer|Basic` credentials; `Cookie` / `Set-Cookie`
   values; JSON keys, JS object keys, form fields and query parameters named like `password`, `passwd`,
   `secret`, `token`, `api_key`, `auth`, `session`, `csrf`... (camelCase names such as `passwordConfirm`
   or `refreshToken` count; words that merely start the same way, such as `passwordless` or `tokenizer`,
   do not); AWS access key ids (`AKIA...`), GitHub
   tokens (`ghp_`, `gho_`, `github_pat_`...), Slack tokens (`xox*`), Stripe keys (`sk_live_`/`sk_test_`),
   OpenAI-style and Anthropic-style `sk-...` keys, and PEM private key blocks.
3. **Playwright-aware.** `fill` / `type` / `pressSequentially` parameters on a selector or locator that
   mentions password (or pin, otp, cvv...), the matching `Fill "..."` step titles, and `type=password`
   input values in DOM snapshots.
4. **storageState.** Cookie and `localStorage` values that have a sensitive name or match a pattern.
5. **Config file.** Extra regexes, extra sensitive key names, an allowlist.

**Propagation.** Secrets found by structure (a typed password, an `Authorization` header, a
`password` field) are remembered and then redacted everywhere else they appear: log lines like
`fill("...")`, request bodies, page HTML, other files in the same run. Turn this off with `--no-propagate`.
Harvested values shorter than `minKnownLength` are redacted where they were found but not searched for
elsewhere; a warning says how many there were (never the values).

## Quick start

```sh
npm i -D pw-tracescrub

npx tracescrub check ./test-results ./playwright-report
```

```sh
# report, exit 1 if anything is found or some content could not be scanned (0 if clean, 2 on usage errors)
tracescrub check ./test-results --env TEST_PASSWORD,API_TOKEN

# write scrubbed copies to ./scrubbed (originals untouched)
tracescrub scrub ./test-results ./playwright-report --out ./scrubbed

# or rewrite in place, typically right before uploading artifacts
tracescrub scrub ./test-results ./playwright-report --in-place --env-file .env.test
```

Options shared by both commands:

| Option | Meaning |
| --- | --- |
| `--env <NAMES>` | Comma-separated env var names whose values are secrets. Repeatable. |
| `--env-file <file>` | Dotenv file; every value is treated as a secret. Repeatable. |
| `--config <file>` | Config file. Defaults to `./tracescrub.config.json` if it exists. |
| `--json` | Machine-readable output. |
| `--json-out <file>` | Also write the JSON report to a file. |
| `--all` | List every finding (the human output shows the first 25 per file). |
| `--no-propagate` | Do not redact harvested secrets in other places. |
| `--allow-unscanned` | Do not fail when some content could not be scanned (see below). |

Content that cannot be scanned (an unreadable zip, a text file that is not UTF-8, a PDF or compressed
blob inside a trace) is listed on stderr as `warning: not scanned: ...`. `check` then exits 1 and
`scrub` exits 2, even if no secrets were found, because that content may still hold secrets. Pass
`--allow-unscanned` to accept it. Images, fonts, audio and video are not scanned either, but they only
produce a note and never fail the run.

With `scrub --out`, a file that could not be scanned at all is left out of the output directory (with a
warning) rather than copied unredacted. A zip that was only partly scanned is still copied, and each
entry that was not scanned is listed. Files of types that `tracescrub` does not look at when walking a
directory (screenshots, videos, the report's trace viewer assets) are copied unchanged.

### Example output

Run against the committed fixtures (real Playwright output from a fake login page, with fake planted secrets):

```text
$ tracescrub check test/fixtures/trace.zip test/fixtures/storageState.json
test/fixtures/trace.zip
  test.trace line 26 $.title  password-fill  tsk_****** (24 chars)
  test.trace line 26 $.params.value  password-fill  tsk_****** (24 chars)
  1-trace.trace line 8 $.params.cookies[0].value  cookie  tsk_****** (27 chars)
  1-trace.trace line 30 $.params.value  password-fill  tsk_****** (24 chars)
  1-trace.trace line 34 $.message  password-fill  tsk_****** (24 chars)
  1-trace.trace line 40 $.snapshot.html[4][5][5][3][1].__playwright_value_  password-input  tsk_****** (24 chars)
  1-trace.network line 2 $.snapshot.request.headers[2].value  authorization  eyJh****** (244 chars)
  1-trace.network line 2 $.snapshot.request.headers[8].value  sensitive-key  tsk_****** (28 chars)
  resources/6b3e23def9e13c84caa9113f936f0dcc6bee01aa.json $.password  sensitive-key  tsk_****** (24 chars)
  ...

test/fixtures/storageState.json
  $.cookies[0].value  cookie  tsk_****** (27 chars)
  $.origins[0].localStorage[0].value  local-storage  tsk_****** (26 chars)

Found 33 potential secret(s) in 2 of 2 file(s). (cookie: 14, sensitive-key: 8, password-fill: 4, jwt: 3, password-input: 2, authorization: 1, local-storage: 1)
Note: 7 image/media entries were not scanned (screenshots and screencast frames are not redacted yet).
```

Each finding shows the file, the zip entry, the line and JSON path, the rule and a masked preview.
The preview shows at most 4 leading characters and never the full value. After `scrub`, the trace
viewer shows the action as `Fill "[REDACTED:password-fill]"` and the header as
`Authorization: Bearer [REDACTED:authorization]`.

## GitHub Action

Run it after your tests and **before** `actions/upload-artifact`:

```yaml
- name: Run Playwright tests
  run: npx playwright test
  env:
    TEST_PASSWORD: ${{ secrets.TEST_PASSWORD }}

- name: Scrub secrets from Playwright artifacts
  if: ${{ !cancelled() }}
  uses: qa-gary-parker/tracescrub@main
  env:
    TEST_PASSWORD: ${{ secrets.TEST_PASSWORD }}
  with:
    paths: test-results playwright-report
    mode: scrub
    env-names: TEST_PASSWORD

- uses: actions/upload-artifact@v7
  if: ${{ !cancelled() }}
  with:
    name: playwright-report
    path: |
      playwright-report
      test-results
```

Or use `mode: check` to fail the job when anything is found (a good guard after a `scrub` step, or on
its own if you would rather fix the tests than upload redacted artifacts).

| Input | Default | Meaning |
| --- | --- | --- |
| `paths` | (required) | Files or directories, separated by spaces or newlines. Missing paths are skipped. |
| `mode` | `check` | `check` reports; `scrub` redacts in place. |
| `env-names` | `''` | Comma-separated env var names whose values are secrets. Set them in the step `env`. |
| `env-file` | `''` | Optional dotenv file. |
| `config` | `''` | Optional config file path. |
| `fail-on-findings` | `true` | In `check` mode, fail the step when secrets are found or content could not be scanned. |
| `allow-unscanned` | `false` | Do not fail when some content could not be scanned. |

Outputs: `findings` (count), `unscanned` (count) and `exit-code`. The action is a composite action.
`dist/` is not committed, so it builds the CLI from source with the runner's `node` (20 or newer):
`npm ci --ignore-scripts`, `tsc`, then prunes dev dependencies. The result is stored with
`actions/cache`, keyed on the runner OS, the Node major version, the lockfile and the sources, so later
runs restore it instead of building.

## Config

`tracescrub.config.json` in the working directory is picked up automatically, or pass `--config`.

```json
{
  "env": ["TEST_PASSWORD", "ADMIN_API_TOKEN"],
  "patterns": [
    { "name": "internal-token", "regex": "itk_[A-Za-z0-9]{24}" },
    { "name": "tenant-key", "regex": "tenantKey=([A-Za-z0-9]+)", "group": 1 }
  ],
  "sensitiveKeys": ["x-tenant-seed", "pin_code"],
  "allowlist": ["not-a-secret-demo-token", "/^example-/"],
  "disableRules": ["form-field"],
  "minKnownLength": 6
}
```

- `patterns`: matches are redacted as `config:<name>`. `group` selects a capture group.
- `sensitiveKeys`: exact names (case-insensitive) for JSON keys, header names, cookie names,
  `localStorage` keys and form fields.
- `allowlist`: values that are never reported. Literal strings, or `/regex/flags`.
- `disableRules`: built-in rule names to switch off (`jwt`, `authorization`, `cookie`, `sensitive-key`,
  `form-field`, `aws-access-key`, `github-token`, `slack-token`, `stripe-key`, `openai-key`,
  `anthropic-key`, `private-key`).

## Limits

- **Images are not redacted yet.** Screenshots and screencast frames (`*.jpeg`, `*.png`) in traces and
  reports are copied unchanged. If a secret is visible on screen (for example a token printed on a page),
  it is still in the frames. Password fields show as dots, but anything else does not.
- **Resource names.** Trace resources are named by the SHA-1 of their content. A scrubbed resource is
  written back under the same name, so the name no longer matches the content. The trace viewer does not
  check this, but other tools might.
- **Binary and encoded bodies.** Base64-encoded HAR bodies, compressed bodies, videos and other binary
  entries are not decoded or scanned. Images, fonts, audio and video only produce a note. Anything else
  that cannot be read (unreadable zips, non-UTF-8 text, PDFs, compressed blobs) is listed as a warning
  and fails `check` (exit 1) and `scrub` (exit 2) unless `--allow-unscanned` is passed.
- **Patterns have false positives and false negatives.** Key-name rules will redact harmless values such
  as a `session` cookie that holds a theme, and will miss secrets stored under neutral names or
  all-lowercase compounds such as `passwordconfirm`. Use
  `--env` / `--env-file` for the values you know about (the most reliable rule), the allowlist for noise,
  and `sensitiveKeys` / `patterns` for your own formats. Cookie values in request headers are always
  redacted.
- **Defence in depth, not a guarantee.** Use dedicated test accounts with short-lived credentials, and
  keep artifact retention short.

## Roadmap

- Black out screencast frames and screenshots around password fields and known values (OCR or
  DOM-snapshot-guided boxes).
- An MCP proxy that serves scrubbed traces to AI agents, so they never see the raw artifact.
- Cypress artifacts (videos, screenshots, `cy.intercept` logs) and other test runners.
- Optional re-hashing of trace resources so names match content again.
- Decoding base64 HAR bodies.

## Development

```sh
npm ci
npm run lint        # typecheck
npm run build
npm test            # vitest: unit + integration tests against test/fixtures

# regenerate fixtures from a real Playwright run (needs a browser)
npx playwright install chromium
npm run fixtures:gen

# open a scrubbed trace in Playwright's own trace viewer, headlessly
npm run build && npm run verify:viewer
```

The fixtures are produced by [`fixtures-gen/`](fixtures-gen/README.md): a fake login page served with
`page.route`, with obviously fake planted values (`tsk_FAKE_...`) and a JWT built from fake claims.

## License

[MIT](LICENSE) (c) 2026 Gary Parker
