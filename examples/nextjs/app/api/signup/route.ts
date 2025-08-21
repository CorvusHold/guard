import { NextRequest, NextResponse } from 'next/server';
import { getClient } from '@/lib/client';
import { isRateLimitError } from '@corvushold/guard-sdk';

const ACCESS_COOKIE = 'guard_access_token';
const REFRESH_COOKIE = 'guard_refresh_token';

function ensureEnv() {
  const baseUrl = process.env.GUARD_BASE_URL;
  if (!baseUrl) throw new Error('GUARD_BASE_URL is not set');
  const tenantId = process.env.GUARD_TENANT_ID;
  if (!tenantId) throw new Error('GUARD_TENANT_ID is not set');
}

export async function POST(req: NextRequest) {
  const { email, password, first_name, last_name } = await req.json();
  if (!email || !password) {
    return NextResponse.json({ error: 'email and password are required' }, { status: 400 });
  }
  ensureEnv();
  const client = getClient();

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '3');
  const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 3;
  const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '2');
  const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 2;

  let attempt = 0;
  while (true) {
    try {
      const res = await client.passwordSignup({ email, password, first_name, last_name });
      const status = res.meta.status;
      if (status === 200 || status === 201) {
        const { access_token, refresh_token } = res.data || ({} as any);
        const out = NextResponse.json({ ok: true }, { status: 201 });
        if (access_token) out.cookies.set(ACCESS_COOKIE, access_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
        if (refresh_token) out.cookies.set(REFRESH_COOKIE, refresh_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
        return out;
      }
      return NextResponse.json(res, { status });
    } catch (e: any) {
      if (isRateLimitError(e) && attempt < maxAttempts - 1) {
        const hinted = e.retryAfter && e.retryAfter > 0 ? e.retryAfter : 1;
        const waitSecs = Math.min(hinted, maxWaitSecs);
        await sleep(waitSecs * 1000);
        attempt++;
        continue;
      }
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
