#!/usr/bin/env node
import fs from 'node:fs';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchWithRetry(url, options, maxAttempts = 8, maxWaitSecs = 10) {
  let attempt = 0;
  while (true) {
    const res = await fetch(url, options);
    let json = null;
    try { json = await res.clone().json(); } catch {}
    // Retry on 429 or explicit rate limit error
    if (res.status === 429 || (json && json.error === 'rate limit exceeded')) {
      if (attempt < maxAttempts - 1) {
        const hinted = Number(res.headers.get('retry-after'));
        const waitSecs = Number.isFinite(hinted) && hinted > 0 ? Math.min(hinted, maxWaitSecs) : 1;
        await sleep(waitSecs * 1000);
        attempt++;
        continue;
      }
    }
    return { res, json };
  }
}

async function main() {
  const envPath = new URL('../.env.local', import.meta.url);
  const env = fs.readFileSync(envPath, 'utf-8');
  const m = env.match(/GUARD_TENANT_ID\s*=\s*([^\n#]+)/);
  if (!m) throw new Error('GUARD_TENANT_ID not found in .env.local');
  const tenantId = m[1].trim();
  const base = process.env.GUARD_BASE_URL || 'http://localhost:8081';
  const adminEmail = process.env.ADMIN_EMAIL || 'nomfa@example.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Password123!';

  // Admin login
  const { res: loginRes, json: loginJson } = await fetchWithRetry(`${base}/v1/auth/password/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tenant_id: tenantId, email: adminEmail, password: adminPassword })
  });
  const adminAccess = loginJson?.access_token;
  if (!loginRes.ok || !adminAccess) {
    console.error('Admin login failed', loginJson || { status: loginRes.status });
    process.exit(2);
  }

  // Configure dev SSO and allowlist to Next.js app origin
  const payload = {
    sso_provider: 'dev',
    sso_redirect_allowlist: 'http://localhost:3001'
  };
  const { res: putRes, json: putJson } = await fetchWithRetry(`${base}/v1/tenants/${tenantId}/settings`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${adminAccess}` },
    body: JSON.stringify(payload)
  });
  if (putRes.status !== 204) {
    console.error('Configure SSO failed', putJson || { status: putRes.status });
    process.exit(3);
  }
  console.log('Configured SSO dev provider and allowlist.');
}

if (typeof fetch !== 'function') {
  console.error('Node fetch not available. Please run with Node 18+');
  process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
