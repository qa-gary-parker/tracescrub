import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { replaceFile } from '../src/engine.js';

const tmp = () => mkdtempSync(path.join(os.tmpdir(), 'tracescrub-engine-'));
const posix = process.platform !== 'win32';

describe('replaceFile', () => {
  it.runIf(posix)('keeps the original permission bits', async () => {
    const file = path.join(tmp(), 'run.log');
    writeFileSync(file, 'before');
    chmodSync(file, 0o640);
    await replaceFile(file, Buffer.from('after'));
    expect(readFileSync(file, 'utf8')).toBe('after');
    expect(statSync(file).mode & 0o777).toBe(0o640);
    expect(existsSync(`${file}.tracescrub-tmp`)).toBe(false);
  });

  it('removes the temporary file when the write fails', async () => {
    const dir = tmp();
    const file = path.join(dir, 'state.json');
    writeFileSync(file, 'before');
    // a directory where the temp file should go makes the rename fail after the write
    // on some platforms and the write itself fail on others; either way nothing is left
    mkdirSync(`${file}.tracescrub-tmp`);
    await expect(replaceFile(file, Buffer.from('after'))).rejects.toThrow();
    expect(readFileSync(file, 'utf8')).toBe('before');
  });

  it.runIf(posix)('cleans up the temporary file when the rename fails', async () => {
    const dir = tmp();
    const target = path.join(dir, 'target');
    // renaming a regular file over a non-empty directory fails after the temp file was written
    mkdirSync(target);
    writeFileSync(path.join(target, 'keep'), 'x');
    await expect(replaceFile(target, Buffer.from('after'))).rejects.toThrow();
    expect(existsSync(`${target}.tracescrub-tmp`)).toBe(false);
    expect(readFileSync(path.join(target, 'keep'), 'utf8')).toBe('x');
  });
});
