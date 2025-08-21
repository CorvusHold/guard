import { NextRequest, NextResponse } from 'next/server';
import { GuardClient, isRateLimitError, isTokensResp, isMfaChallengeResp } from '@corvushold/guard-sdk';

const ACCESS_COOKIE = 'guard_access_token';
const REFRESH_COOKIE = 'guard_refresh_token';

function getClient() {
  const baseUrl = process.env.GUARD_BASE_URL;
  if (!baseUrl) throw new Error('GUARD_BASE_URL is not set');
  const tenantId = process.env.GUARD_TENANT_ID;
  return new GuardClient({ baseUrl, tenantId });
}

export async function POST(req: NextRequest) {
  const { email, password } = await req.json();
  if (!email || !password) {
    return NextResponse.json({ error: 'email and password are required' }, { status: 400 });
  }

  const client = getClient();
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '3');
  const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 3;
  const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '2');
  const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 2;
  let attempt = 0;
  let res: any;
  while (true) {
    try {
      res = await client.passwordLogin({ email, password });
      break;
    } catch (e: any) {
      if (isRateLimitError(e) && attempt < maxAttempts - 1) {
        const hinted = e.retryAfter && e.retryAfter > 0 ? e.retryAfter : 1;
        const waitSecs = Math.min(hinted, maxWaitSecs);
        await sleep(waitSecs * 1000);
        attempt++;
        continue;
      }
      const status = typeof e?.status === 'number' ? e.status : 500;
      return NextResponse.json({ error: e?.message || 'Login failed' }, { status });
    }
  }

  if (res.meta.status === 200 && isTokensResp(res.data)) {
    const { access_token, refresh_token } = res.data;
    const out = NextResponse.json({ ok: true }, { status: 200 });
    if (access_token) out.cookies.set(ACCESS_COOKIE, access_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    if (refresh_token) out.cookies.set(REFRESH_COOKIE, refresh_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    return out;
  }

  if (res.meta.status === 202 && isMfaChallengeResp(res.data)) {
    const { challenge_token, methods } = res.data;
    return NextResponse.json({ challenge_token, methods }, { status: 202 });
  }

  return NextResponse.json({ error: res.error ?? 'Login failed' }, { status: res.meta.status });
}
