#!/usr/bin/env node
import fs from 'node:fs';

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
  const loginRes = await fetch(`${base}/v1/auth/password/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tenant_id: tenantId, email: adminEmail, password: adminPassword })
  });
  const loginJson = await loginRes.json();
  const adminAccess = loginJson?.access_token;
  if (!loginRes.ok || !adminAccess) {
    console.error('Admin login failed', loginJson);
    process.exit(2);
  }

  // Signup owner user
  const ts = Date.now();
  const ownerEmail = `owner.e2e.${ts}@example.com`;
  const ownerPassword = 'Password123!';
  const signupRes = await fetch(`${base}/v1/auth/password/signup`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tenant_id: tenantId, email: ownerEmail, password: ownerPassword, first_name: 'Owner', last_name: 'User' })
  });
  const signupJson = await signupRes.json();
  const ownerAccess = signupJson?.access_token;
  if (!signupRes.ok || !ownerAccess) {
    console.error('Owner signup failed', signupJson);
    process.exit(3);
  }

  // Introspect to get user id
  const introRes = await fetch(`${base}/v1/auth/introspect`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: ownerAccess })
  });
  const introJson = await introRes.json();
  const userId = introJson?.user_id || introJson?.sub || (introJson?.user && introJson.user.id);
  if (!introRes.ok || !userId) {
    console.error('Introspect failed', introJson);
    process.exit(4);
  }

  // Grant roles admin+owner
  const rolesRes = await fetch(`${base}/v1/auth/admin/users/${encodeURIComponent(userId)}/roles`, {
    method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${adminAccess}` },
    body: JSON.stringify({ roles: ['admin', 'owner'] })
  });
  if (!(rolesRes.status === 200 || rolesRes.status === 204)) {
    console.error('Roles update failed', rolesRes.status);
    process.exit(5);
  }

  // Print exports for shell eval
  process.stdout.write(`export OWNER_EMAIL=${ownerEmail}\n`);
  process.stdout.write(`export OWNER_PASSWORD=${ownerPassword}\n`);
}

// Node 18+ has global fetch
if (typeof fetch !== 'function') {
  console.error('Node fetch not available. Please run with Node 18+');
  process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
