import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FIXTURES } from './helpers.js';

const cli = path.join(import.meta.dirname, '..', 'dist', 'cli.js');

describe.skipIf(!existsSync(cli))('built CLI (dist/cli.js)', () => {
  it('prints the version', () => {
    expect(execFileSync(process.execPath, [cli, '--version'], { encoding: 'utf8' }).trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('exits 1 on the fixtures and 2 on a usage error', () => {
    expect(spawnSync(process.execPath, [cli, 'check', FIXTURES]).status).toBe(1);
    expect(spawnSync(process.execPath, [cli, 'check']).status).toBe(2);
  });
});
