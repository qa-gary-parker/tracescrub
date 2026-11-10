import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildDetectorOptions, loadConfig, parseEnvFile, validateConfig } from '../src/config.js';
import { UsageError } from '../src/errors.js';

describe('parseEnvFile', () => {
  it('parses common dotenv syntax', () => {
    const env = parseEnvFile(
      ['# comment', 'A=plain', 'export B="quoted value"', "C='single'", 'D=value # trailing comment', '', 'not a line'].join('\n'),
    );
    expect(env).toEqual({ A: 'plain', B: 'quoted value', C: 'single', D: 'value' });
  });
});

describe('config', () => {
  it('validates shapes', () => {
    expect(() => validateConfig([])).toThrow(UsageError);
    expect(() => validateConfig({ allowlist: [1] })).toThrow(UsageError);
    expect(() => validateConfig({ patterns: [{ name: 'x', regex: '(' }] })).toThrow(/invalid regex/);
    expect(validateConfig({ patterns: [{ name: 'x', regex: 'a+' }], sensitiveKeys: ['k'] })).toMatchObject({
      sensitiveKeys: ['k'],
      patterns: [{ name: 'x', regex: 'a+' }],
    });
  });

  it('loads tracescrub.config.json from cwd when present, and errors on a missing explicit file', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'tracescrub-cfg-'));
    expect(loadConfig(undefined, dir)).toEqual({});
    writeFileSync(path.join(dir, 'tracescrub.config.json'), JSON.stringify({ allowlist: ['x'] }));
    expect(loadConfig(undefined, dir).allowlist).toEqual(['x']);
    expect(() => loadConfig(path.join(dir, 'nope.json'))).toThrow(UsageError);
  });

  it('collects env values by name, from env files and from config', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'tracescrub-env-'));
    const envFile = path.join(dir, '.env');
    writeFileSync(envFile, 'FROM_FILE=file-secret-value\n');
    writeFileSync(path.join(dir, 'tracescrub.config.json'), JSON.stringify({ env: ['FROM_CONFIG'] }));
    const warnings: string[] = [];
    const opts = buildDetectorOptions({
      env: ['A_SECRET,MISSING'],
      envFile: [envFile],
      cwd: dir,
      environment: { A_SECRET: 'env-secret-value', FROM_CONFIG: 'config-secret-value' },
      warn: (m) => warnings.push(m),
    });
    expect(opts.knownValues).toEqual([
      { value: 'config-secret-value', rule: 'env:FROM_CONFIG' },
      { value: 'env-secret-value', rule: 'env:A_SECRET' },
      { value: 'file-secret-value', rule: 'env:FROM_FILE' },
    ]);
    expect(warnings).toEqual(['env var MISSING is not set; skipping']);
  });
});
