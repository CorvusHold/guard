#!/usr/bin/env node
/*
Sets GUARD_RATE_LIMIT_MAX_ATTEMPTS in examples/nextjs/.env.local
Usage:
  node scripts/set-rate-attempts.js 5
  npm run set:rate-attempts -- 5
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
if (!arg) die('Usage: node scripts/set-rate-attempts.js <attempts>');
const attempts = Number(arg);
if (!Number.isFinite(attempts) || attempts <= 0) die('Attempts must be a positive number');

let content = '';
if (fs.existsSync(envPath)) {
  content = fs.readFileSync(envPath, 'utf8');
}
const lines = content.split(/\r?\n/);
const filtered = lines.filter(l => !/^\s*GUARD_RATE_LIMIT_MAX_ATTEMPTS\s*=/.test(l));
filtered.push(`GUARD_RATE_LIMIT_MAX_ATTEMPTS=${attempts}`);
fs.writeFileSync(envPath, filtered.join('\n') + '\n', 'utf8');
console.log(`Set GUARD_RATE_LIMIT_MAX_ATTEMPTS=${attempts} in .env.local`);
