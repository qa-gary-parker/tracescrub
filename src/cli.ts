#!/usr/bin/env node
import { main } from './main.js';

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`tracescrub: ${err?.stack ?? err}\n`);
    process.exitCode = 3;
  },
);
