import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { CustomPattern, DetectorOptions, KnownValue } from './detector.js';
import { UsageError } from './errors.js';

export interface TracescrubConfig {
  /** Extra regexes. Each match is redacted as config:<name>. */
  patterns?: CustomPattern[];
  /** Extra key names (JSON keys, header names, form fields, cookie names) treated as sensitive. */
  sensitiveKeys?: string[];
  /** Values never reported. Literal strings, or "/regex/flags". */
  allowlist?: string[];
  /** Environment variable names whose values are treated as secrets. */
  env?: string[];
  /** Built-in rules to switch off, e.g. "form-field". */
  disableRules?: string[];
  /** Minimum length for known values (env values, harvested secrets). Default 6. */
  minKnownLength?: number;
}

export const DEFAULT_CONFIG_FILE = 'tracescrub.config.json';

export function loadConfig(file: string | undefined, cwd = process.cwd()): TracescrubConfig {
  let p = file;
  if (!p) {
    const auto = path.join(cwd, DEFAULT_CONFIG_FILE);
    if (!existsSync(auto)) return {};
    p = auto;
  }
  if (!existsSync(p)) throw new UsageError(`config file not found: ${p}`);
  let cfg: unknown;
  try {
    cfg = JSON.parse(readFileSync(p, 'utf8'));
  } catch (e) {
    throw new UsageError(`invalid JSON in config file ${p}: ${(e as Error).message}`);
  }
  return validateConfig(cfg, p);
}

export function validateConfig(cfg: unknown, source = 'config'): TracescrubConfig {
  if (typeof cfg !== 'object' || cfg === null || Array.isArray(cfg)) {
    throw new UsageError(`${source}: expected a JSON object`);
  }
  const c = cfg as Record<string, unknown>;
  const strArray = (k: string) => {
    const v = c[k];
    if (v === undefined) return undefined;
    if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) {
      throw new UsageError(`${source}: "${k}" must be an array of strings`);
    }
    return v as string[];
  };
  const out: TracescrubConfig = {
    sensitiveKeys: strArray('sensitiveKeys'),
    allowlist: strArray('allowlist'),
    env: strArray('env'),
    disableRules: strArray('disableRules'),
  };
  if (c.minKnownLength !== undefined) {
    if (typeof c.minKnownLength !== 'number' || c.minKnownLength < 1) {
      throw new UsageError(`${source}: "minKnownLength" must be a positive number`);
    }
    out.minKnownLength = c.minKnownLength;
  }
  if (c.patterns !== undefined) {
    if (!Array.isArray(c.patterns)) throw new UsageError(`${source}: "patterns" must be an array`);
    out.patterns = c.patterns.map((p, i) => {
      const pp = p as Record<string, unknown>;
      if (typeof pp?.name !== 'string' || typeof pp?.regex !== 'string') {
        throw new UsageError(`${source}: patterns[${i}] needs string "name" and "regex"`);
      }
      try {
        new RegExp(pp.regex, typeof pp.flags === 'string' ? pp.flags : '');
      } catch (e) {
        throw new UsageError(`${source}: patterns[${i}] has an invalid regex: ${(e as Error).message}`);
      }
      return {
        name: pp.name,
        regex: pp.regex,
        flags: typeof pp.flags === 'string' ? pp.flags : undefined,
        group: typeof pp.group === 'number' ? pp.group : undefined,
      };
    });
  }
  return out;
}

/** Minimal dotenv parser: KEY=VALUE, optional "export", quotes, # comments. */
export function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2];
    const q = v[0];
    if ((q === '"' || q === "'") && v.lastIndexOf(q) > 0) {
      v = v.slice(1, v.lastIndexOf(q));
      if (q === '"') v = v.replace(/\\n/g, '\n').replace(/\\"/g, '"');
    } else {
      v = v.replace(/\s+#.*$/, '').trim();
    }
    out[m[1]] = v;
  }
  return out;
}

export interface SourceOptions {
  env?: string[];
  envFile?: string[];
  config?: string;
  cwd?: string;
  environment?: NodeJS.ProcessEnv;
  warn?: (msg: string) => void;
}

/** Combine CLI flags, config file and environment into detector options. */
export function buildDetectorOptions(o: SourceOptions): DetectorOptions {
  const cfg = loadConfig(o.config, o.cwd);
  const environment = o.environment ?? process.env;
  const warn = o.warn ?? (() => {});
  const known: KnownValue[] = [];
  const names = [...(cfg.env ?? []), ...(o.env ?? [])]
    .flatMap((n) => n.split(','))
    .map((n) => n.trim())
    .filter(Boolean);
  for (const name of new Set(names)) {
    const v = environment[name];
    if (v === undefined || v === '') warn(`env var ${name} is not set; skipping`);
    else known.push({ value: v, rule: `env:${name}` });
  }
  for (const f of o.envFile ?? []) {
    if (!existsSync(f)) throw new UsageError(`env file not found: ${f}`);
    const vars = parseEnvFile(readFileSync(f, 'utf8'));
    for (const [k, v] of Object.entries(vars)) known.push({ value: v, rule: `env:${k}` });
  }
  return {
    knownValues: known,
    patterns: cfg.patterns,
    sensitiveKeys: cfg.sensitiveKeys,
    allowlist: cfg.allowlist,
    disableRules: cfg.disableRules,
    minKnownLength: cfg.minKnownLength,
  };
}
