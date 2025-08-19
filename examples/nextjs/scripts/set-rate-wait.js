#!/usr/bin/env node
/*
Sets GUARD_RATE_LIMIT_MAX_WAIT_SECS in examples/nextjs/.env.local
Usage:
  node scripts/set-rate-wait.js 2
  npm run set:rate-wait -- 2
*/
import fs from 'fs';
import path from 'path';

const projectRoot = path.resolve(process.cwd());
const envPath = path.join(projectRoot, '.env.local');

function die(msg) {
  console.error(msg);
  process.exit(1);
}

const arg = process.argv[2];
if (!arg) die('Usage: node scripts/set-rate-wait.js <seconds>');
const secs = Number(arg);
if (!Number.isFinite(secs) || secs <= 0) die('Seconds must be a positive number');

let content = '';
if (fs.existsSync(envPath)) {
  content = fs.readFileSync(envPath, 'utf8');
}
const lines = content.split(/\r?\n/);
const filtered = lines.filter(l => !/^\s*GUARD_RATE_LIMIT_MAX_WAIT_SECS\s*=/.test(l));
filtered.push(`GUARD_RATE_LIMIT_MAX_WAIT_SECS=${secs}`);
fs.writeFileSync(envPath, filtered.join('\n') + '\n', 'utf8');
console.log(`Set GUARD_RATE_LIMIT_MAX_WAIT_SECS=${secs} in .env.local`);
