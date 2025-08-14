#!/usr/bin/env node
import { readFile, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..'); // sdk/spec/scripts -> repo root

const SPEC_FILE = path.join(repoRoot, 'sdk', 'spec', 'openapi.json');
const OUT_FILE = path.join(repoRoot, 'sdk', 'spec', 'operations.json');

const args = process.argv.slice(2);
const WRITE = args.includes('--write');

function stableStringify(obj) {
  const sortObjectDeep = (value) => {
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
  };
  return JSON.stringify(sortObjectDeep(obj), null, 2) + '\n';
}

async function fileExists(p) {
  try { await access(p); return true; } catch { return false; }
}

function first2xxResponse(responses) {
  if (!responses || typeof responses !== 'object') return null;
  const codes = Object.keys(responses).filter((c) => /^2\d\d$/.test(c)).sort();
  const code = codes[0];
  if (!code) return null;
  const r = responses[code];
  // OpenAPI 3: content-based
  const content = r && r.content && (r.content['application/json'] || r.content['*/*']);
  if (content && content.schema) return { status: code, schema: content.schema };
  // Swagger 2: schema directly under response
  if (r && r.schema) return { status: code, schema: r.schema };
  // Fallback: no schema
  return { status: code };
}

function errorResponses(responses) {
  if (!responses || typeof responses !== 'object') return [];
  return Object.entries(responses)
    .filter(([code]) => /^(4\d\d|5\d\d)$/.test(code))
    .map(([code, r]) => {
      const content = r && r.content && (r.content['application/json'] || r.content['*/*']);
      const schema = content && content.schema ? content.schema : (r && r.schema ? r.schema : null);
      return { status: code, schema };
    })
    .sort((a, b) => Number(a.status) - Number(b.status));
}

function requestBodyRef(op) {
  // OpenAPI 3
  const rb = op.requestBody;
  if (rb) {
    const content = rb.content && (rb.content['application/json'] || rb.content['*/*']);
    const schema = content && content.schema ? content.schema : null;
    if (schema) return schema;
  }
  // Swagger 2: parameters with in: body
  if (Array.isArray(op.parameters)) {
    const bodyParam = op.parameters.find((p) => p && p.in === 'body' && p.schema);
    if (bodyParam && bodyParam.schema) return bodyParam.schema;
  }
  return null;
}

async function loadSpec() {
  const buf = await readFile(SPEC_FILE, 'utf8');
  return JSON.parse(buf);
}

async function main() {
  try {
    const spec = await loadSpec();
    const paths = spec.paths || {};

    const ops = [];
    for (const [p, methods] of Object.entries(paths)) {
      for (const [m, op] of Object.entries(methods)) {
        const method = m.toLowerCase();
        if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) continue;
        // Use provided operationId when present; else synthesize stable id from method+path
        let operationId = op.operationId || null;
        if (!operationId) {
          const synth = `${method}_${p}`
            .replace(/^\//, '')
            .replace(/\{([^}]+)\}/g, 'by_$1')
            .replace(/[^a-zA-Z0-9]+/g, '_')
            .replace(/_+/g, '_')
            .replace(/^_+|_+$/g, '')
            .toLowerCase();
          operationId = synth || null;
        }
        const success = first2xxResponse(op.responses);
        ops.push({
          operationId,
          method,
          path: p,
          tags: op.tags || [],
          summary: op.summary || '',
          requestBody: requestBodyRef(op),
          success,
          errors: errorResponses(op.responses),
        });
      }
    }

    ops.sort((a, b) => a.operationId.localeCompare(b.operationId));
    const payload = {
      generatedAt: new Date().toISOString(),
      info: { title: spec.info?.title, version: spec.info?.version },
      count: ops.length,
      operations: ops,
    };

    const outStr = stableStringify(payload);
    const hasExisting = await fileExists(OUT_FILE);
    if (!WRITE) {
      if (hasExisting) {
        const existing = await readFile(OUT_FILE, 'utf8');
        if (existing === outStr) {
          console.log('operations.json is up-to-date');
          return;
        }
        console.error('operations.json is out-of-date. Run: node sdk/spec/scripts/generate-operations.mjs --write');
        process.exit(1);
      } else {
        console.error('operations.json missing. Run: node sdk/spec/scripts/generate-operations.mjs --write');
        process.exit(1);
      }
    }

    await writeFile(OUT_FILE, outStr);
    console.log('Wrote', path.relative(repoRoot, OUT_FILE));
  } catch (err) {
    console.error('generate-operations failed:', err.message);
    process.exit(2);
  }
}

main();
