import { NextRequest, NextResponse } from 'next/server';
import { GuardClient, isRateLimitError } from '@corvushold/guard-sdk';

const ACCESS_COOKIE = 'guard_access_token';
const REFRESH_COOKIE = 'guard_refresh_token';

function getClient() {
  const baseUrl = process.env.GUARD_BASE_URL;
  if (!baseUrl) throw new Error('GUARD_BASE_URL is not set');
  const tenantId = process.env.GUARD_TENANT_ID;
  return new GuardClient({ baseUrl, tenantId });
}

export async function POST(req: NextRequest) {
  const refresh = req.cookies.get(REFRESH_COOKIE)?.value ?? null;
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
      res = await client.logout({ refresh_token: refresh });
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
      // Ensure cookies are cleared even if logout fails
      const outErr = NextResponse.json({ ok: true }, { status });
      outErr.cookies.set(REFRESH_COOKIE, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0, expires: new Date(0), secure: false });
      outErr.cookies.set(ACCESS_COOKIE, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0, expires: new Date(0), secure: false });
      return outErr;
    }
  }

  // Return JSON 200 so Set-Cookie applies reliably on fetch-based logout.
  const out = NextResponse.json({ ok: true }, { status: 200 });
  // Clear cookies on logout regardless of backend status
  out.cookies.set(REFRESH_COOKIE, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0, expires: new Date(0), secure: false });
  out.cookies.set(ACCESS_COOKIE, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0, expires: new Date(0), secure: false });
  return out;
}

export async function GET(req: NextRequest) {
  // Best-effort revoke on backend; then clear browser cookies and redirect.
  const refresh = req.cookies.get(REFRESH_COOKIE)?.value ?? null;
  if (refresh) {
    const client = getClient();
    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
    const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '3');
    const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 3;
    const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '2');
    const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 2;
    let attempt = 0;
    while (true) {
      try {
        await client.logout({ refresh_token: refresh });
        break;
      } catch (e: any) {
        if (isRateLimitError(e) && attempt < maxAttempts - 1) {
          const hinted = e.retryAfter && e.retryAfter > 0 ? e.retryAfter : 1;
          const waitSecs = Math.min(hinted, maxWaitSecs);
          await sleep(waitSecs * 1000);
          attempt++;
          continue;
        }
        break; // ignore other errors during GET logout
      }
    }
  }
  const out = NextResponse.redirect(new URL('/', req.url), { status: 303 });
  out.cookies.set(REFRESH_COOKIE, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0, expires: new Date(0), secure: false });
  out.cookies.set(ACCESS_COOKIE, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0, expires: new Date(0), secure: false });
  return out;
}
