#!/usr/bin/env node
import { runCli } from '../dist/cli.js';

runCli()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`agentledger: unexpected error: ${message}`);
    process.exitCode = 2;
  });
