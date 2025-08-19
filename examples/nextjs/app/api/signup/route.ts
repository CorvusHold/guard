import { NextRequest, NextResponse } from 'next/server';

const ACCESS_COOKIE = 'guard_access_token';
const REFRESH_COOKIE = 'guard_refresh_token';

function getBaseAndTenant() {
  const baseUrl = process.env.GUARD_BASE_URL;
  if (!baseUrl) throw new Error('GUARD_BASE_URL is not set');
  const tenantId = process.env.GUARD_TENANT_ID;
  if (!tenantId) throw new Error('GUARD_TENANT_ID is not set');
  return { baseUrl, tenantId };
}

export async function POST(req: NextRequest) {
  const { email, password, first_name, last_name } = await req.json();
  if (!email || !password) {
    return NextResponse.json({ error: 'email and password are required' }, { status: 400 });
  }

  const { baseUrl, tenantId } = getBaseAndTenant();

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '3');
  const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 3;
  const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '2');
  const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 2;

  let attempt = 0;
  while (true) {
    try {
      const r = await fetch(`${baseUrl}/v1/auth/password/signup`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenantId, email, password, first_name, last_name }),
      });

      const status = r.status;
      // 429 handling with Retry-After
      if (status === 429 && attempt < maxAttempts - 1) {
        const retryAfter = r.headers.get('retry-after');
        const hinted = retryAfter ? Number(retryAfter) : 1;
        const waitSecs = Number.isFinite(hinted) && hinted > 0 ? Math.min(hinted, maxWaitSecs) : 1;
        await sleep(waitSecs * 1000);
        attempt++;
        continue;
      }

      const j = status === 204 ? {} : await r.json().catch(() => ({}));

      // Treat 200 or 201 as success
      if (status === 200 || status === 201) {
        const { access_token, refresh_token } = j as any;
        const out = NextResponse.json({ ok: true }, { status: 201 });
        if (access_token) out.cookies.set(ACCESS_COOKIE, access_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
        if (refresh_token) out.cookies.set(REFRESH_COOKIE, refresh_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
        return out;
      }

      // Surface backend error message when available
      return NextResponse.json({ error: (j && (j.error || j.message)) || 'Signup failed' }, { status });
    } catch (e: any) {
      if (attempt < maxAttempts - 1) {
        await sleep(1000);
        attempt++;
        continue;
      }
      const msg = e?.message || 'Signup failed';
      return NextResponse.json({ error: msg }, { status: 500 });
    }
  }
}
