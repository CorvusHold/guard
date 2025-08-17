#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..'); // sdk/spec/scripts -> repo root

const SOURCE_SPEC = path.join(repoRoot, 'docs', 'swagger.json');
const MIRROR_SPEC = path.join(repoRoot, 'sdk', 'spec', 'openapi.json');

const args = process.argv.slice(2);
const WRITE = args.includes('--write');

function sortObjectDeep(value) {
  if (Array.isArray(value)) return value.map(sortObjectDeep);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, k) => {
        acc[k] = sortObjectDeep(value[k]);
        return acc;
      }, {});
  }
  return value;
}

async function loadJson(file) {
  const buf = await readFile(file, 'utf8');
  return JSON.parse(buf);
}

async function main() {
  try {
    const src = await loadJson(SOURCE_SPEC);
    const dst = await loadJson(MIRROR_SPEC).catch(() => ({}));

    const srcNorm = JSON.stringify(sortObjectDeep(src));
    const dstNorm = JSON.stringify(sortObjectDeep(dst));

    if (srcNorm === dstNorm) {
      console.log('Spec in sdk/spec/openapi.json is in sync with docs/swagger.json');
      return;
    }

    if (WRITE) {
      await writeFile(MIRROR_SPEC, JSON.stringify(src, null, 2) + '\n');
      console.log('Updated sdk/spec/openapi.json from docs/swagger.json');
      return;
    }

    console.error('Spec drift detected between docs/swagger.json and sdk/spec/openapi.json');
    console.error('Run: node sdk/spec/scripts/sync-spec.mjs --write');
    process.exit(1);
  } catch (err) {
    console.error('sync-spec failed:', err.message);
    process.exit(2);
  }
}

main();
