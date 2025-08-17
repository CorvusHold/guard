#!/usr/bin/env node
/*
  Guard TS SDK Conformance Runner
  - Loads scenario JSON files from sdk/conformance/scenarios/
  - Executes HTTP requests against BASE_URL
  - Supports simple {{var}} interpolation from env and stored values
  - Validates status, headers (exact match for provided keys), and bodyContains (subset match)
  - Stores selected response JSON values by simple dot-path (e.g., data.access_token)
*/

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { authenticator } from 'otplib';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// root resolves to sdk/ (two up from ts/scripts)
const root = path.resolve(__dirname, '../../');
const scenariosDir = path.resolve(root, 'conformance/scenarios');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function listScenarioFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => path.join(dir, f));
}

function interpolate(val, ctx) {
  if (val == null) return val;
  if (typeof val === 'string') {
    return val.replace(/\{\{\s*([A-Za-z0-9_\.\-]+)\s*\}\}/g, (_, k) => {
      const v = getVar(ctx, k);
      return v == null ? '' : String(v);
    });
  }
  if (Array.isArray(val)) return val.map((x) => interpolate(x, ctx));
  if (typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) out[k] = interpolate(v, ctx);
    return out;
  }
  return val;
}

function getVar(ctx, key) {
  // support dot path into ctx
  const parts = key.split('.');
  let cur = ctx;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object' || !(p in cur)) return undefined;
    cur = cur[p];
  }
  return cur;
}

function getByDotPath(obj, dotPath) {
  const parts = dotPath.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object' || !(p in cur)) return undefined;
    cur = cur[p];
  }
  return cur;
}

function matchesSubset(expected, actual) {
  if (expected == null) return true;
  if (typeof expected !== 'object') return expected === actual;
  // Treat empty object {} as an existence check (any type), e.g., { access_token: {} }
  if (!Array.isArray(expected) && Object.keys(expected).length === 0) {
    return actual !== undefined && actual !== null;
  }
  if (typeof actual !== 'object' || actual == null) return false;
  for (const [k, v] of Object.entries(expected)) {
    if (!matchesSubset(v, actual[k])) return false;
  }
  return true;
}

async function runScenario(file, baseUrl, baseCtx) {
  const scenario = readJson(file);
  const name = scenario.name || path.basename(file);
  const ctx = { ...baseCtx };
  // Apply per-scenario environment overrides if provided (schema: setup.env)
  const setupEnv = scenario.setup && scenario.setup.env ? scenario.setup.env : null;
  if (setupEnv && typeof setupEnv === 'object') {
    // Allow overrides to reference existing env/ctx variables via interpolation
    const overrides = interpolate(setupEnv, { ...process.env, ...ctx });
    Object.assign(ctx, overrides);
  }

  // Ensure TOTP_CODE is computed after overrides if a secret is present (fresh for this scenario)
  if (ctx.TOTP_SECRET) {
    try {
      ctx.TOTP_CODE = authenticator.generate(String(ctx.TOTP_SECRET));
    } catch (_) {
      // ignore
    }
  }
  const requires = Array.isArray(scenario.requiresEnv) ? scenario.requiresEnv : [];
  const missing = requires.filter((k) => getVar({ ...process.env, ...ctx }, k) == null || getVar({ ...process.env, ...ctx }, k) === '');
  if (missing.length > 0) {
    console.log(`\nScenario: ${name}`);
    console.log(`  ↷ Skipping (missing env): ${missing.join(', ')}`);
    return { passed: 0, failed: 0, skipped: 1 };
  }

  // Optional scenario-level pause before running steps
  const waitMs = Number(scenario?.setup?.waitMs || 0);
  if (waitMs > 0) {
    await new Promise((r) => setTimeout(r, waitMs));
  }

  console.log(`\nScenario: ${name}`);

  let passed = 0;
  let failed = 0;

  for (let i = 0; i < scenario.steps.length; i++) {
    const step = scenario.steps[i];
    // Optional per-step delay
    const stepWait = Number(step?.waitMs || 0);
    if (stepWait > 0) {
      await new Promise((r) => setTimeout(r, stepWait));
    }
    // If this step uses {{TOTP_CODE}}, refresh it just-in-time to avoid window roll-over
    if (ctx.TOTP_SECRET) {
      try {
        const rawBody = step?.request?.body;
        const usesTOTP = typeof rawBody === 'string'
          ? rawBody.includes('{{TOTP_CODE}}')
          : JSON.stringify(rawBody || '').includes('{{TOTP_CODE}}');
        if (usesTOTP) {
          ctx.TOTP_CODE = authenticator.generate(String(ctx.TOTP_SECRET));
        }
      } catch (_) {
        // ignore
      }
    }
    const req = interpolate(step.request, ctx);

    // Build URL
    const url = new URL(req.path, baseUrl);
    if (req.query && typeof req.query === 'object') {
      for (const [k, v] of Object.entries(req.query)) {
        if (v != null) url.searchParams.set(k, String(v));
      }
    }

    // Headers
    const headers = new Headers();
    if (req.headers && typeof req.headers === 'object') {
      for (const [k, v] of Object.entries(req.headers)) {
        if (v != null) headers.set(k, String(v));
      }
    }
    let body;
    if (req.body !== undefined) {
      body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      if (!headers.has('content-type')) headers.set('content-type', 'application/json');
    }

    const res = await fetch(url, { method: req.method, headers, body });
    const resText = await res.text();
    let resJson = null;
    try {
      resJson = resText ? JSON.parse(resText) : null;
    } catch (_) {
      // ignore non-JSON
    }

    // Validate
    const exp = step.expect || {};
    let ok = true;
    const errs = [];

    if (typeof exp.status === 'number' && res.status !== exp.status) {
      ok = false;
      errs.push(`status expected ${exp.status}, got ${res.status}`);
    }

    if (exp.headers && typeof exp.headers === 'object') {
      for (const [k, v] of Object.entries(exp.headers)) {
        const got = res.headers.get(k);
        if (got !== v) {
          ok = false;
          errs.push(`header ${k} expected ${v}, got ${got}`);
        }
      }
    }

    if (exp.bodyContains !== undefined) {
      if (!matchesSubset(exp.bodyContains, resJson)) {
        ok = false;
        errs.push(`body does not contain expected subset`);
      }
    }

    // Store
    if (step.store && typeof step.store === 'object' && resJson) {
      for (const [alias, dotPath] of Object.entries(step.store)) {
        const val = getByDotPath(resJson, dotPath);
        if (val !== undefined) ctx[alias] = val;
      }
    }

    if (ok) {
      passed++;
      console.log(`  ✓ Step ${i + 1} ${req.method} ${req.path}`);
    } else {
      failed++;
      console.log(`  ✗ Step ${i + 1} ${req.method} ${req.path}`);
      for (const e of errs) console.log(`    - ${e}`);
      console.log(`    Response: ${res.status} ${resText?.slice(0, 500)}`);
    }
  }

  console.log(`Result: ${passed} passed, ${failed} failed`);
  return { passed, failed, skipped: 0 };
}

async function main() {
  const baseUrl = process.env.BASE_URL;
  if (!baseUrl) {
    console.error('BASE_URL is required, e.g., BASE_URL=http://localhost:8080 npm run conformance');
    process.exit(2);
  }

  let files = listScenarioFiles(scenariosDir);
  if (files.length === 0) {
    console.log(`No scenario files found in ${scenariosDir}`);
    process.exit(0);
  }

  // Optional filter: run only scenarios whose filename matches or includes SCENARIO/SCENARIO_FILTER
  const only = (process.env.SCENARIO || process.env.SCENARIO_FILTER || '').trim();
  if (only) {
    const match = (f) => {
      const b = path.basename(f);
      return b === only || b.includes(only);
    };
    const filtered = files.filter(match);
    if (filtered.length === 0) {
      console.log(`No scenarios matched filter "${only}". Available: ${files.map((f) => path.basename(f)).join(', ')}`);
      process.exit(1);
    }
    console.log(`Filtering scenarios by "${only}": ${filtered.map((f) => path.basename(f)).join(', ')}`);
    files = filtered;
  }

  const baseCtx = {
    TENANT_ID: process.env.TENANT_ID,
    EMAIL: process.env.EMAIL,
    PASSWORD: process.env.PASSWORD,
    ACCESS_TOKEN: process.env.ACCESS_TOKEN,
    MAGIC_TOKEN: process.env.MAGIC_TOKEN,
    TOTP_SECRET: process.env.TOTP_SECRET,
    TOTP_CODE: process.env.TOTP_CODE,
  };

  // Optionally auto-fetch MAGIC_TOKEN from test-only endpoint.
  const shouldFetchMagic = (process.env.AUTO_MAGIC_TOKEN || '').toLowerCase() === 'true';
  if (shouldFetchMagic && !baseCtx.MAGIC_TOKEN && baseCtx.TENANT_ID && baseCtx.EMAIL) {
    try {
      const url = new URL('/v1/auth/magic/token', baseUrl);
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tenant_id: baseCtx.TENANT_ID, email: baseCtx.EMAIL }),
      });
      if (res.ok) {
        const json = await res.json();
        if (json?.token) {
          baseCtx.MAGIC_TOKEN = json.token;
          console.log('  • Retrieved MAGIC_TOKEN from test endpoint');
        }
      } else {
        const t = await res.text();
        console.warn(`  • Failed to fetch MAGIC_TOKEN (${res.status}): ${t.slice(0, 200)}`);
      }
    } catch (e) {
      console.warn('  • Error fetching MAGIC_TOKEN:', e?.message || e);
    }
  }

  let totalPassed = 0;
  let totalFailed = 0;
  let totalSkipped = 0;
  for (const f of files) {
    const { passed, failed, skipped } = await runScenario(f, baseUrl, baseCtx);
    totalPassed += passed;
    totalFailed += failed;
    totalSkipped += skipped;
  }

  console.log(`\nConformance summary: ${totalPassed} passed, ${totalFailed} failed, ${totalSkipped} skipped`);
  process.exit(totalFailed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
