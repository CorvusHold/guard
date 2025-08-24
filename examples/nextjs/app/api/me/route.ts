import { NextRequest, NextResponse } from 'next/server';
import { getClientFromCookies } from '@/lib/client';
import { isRateLimitError } from '@corvushold/guard-sdk';

export async function GET(req: NextRequest) {
  const client = getClientFromCookies(req);
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '5');
  const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 5;
  const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '4');
  const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 4;
  const envUnauthAttempts = Number(process.env.GUARD_ME_UNAUTH_ATTEMPTS ?? '5');
  const unauthAttempts = Number.isFinite(envUnauthAttempts) && envUnauthAttempts > 0 ? envUnauthAttempts : 5;
  const envUnauthDelay = Number(process.env.GUARD_ME_UNAUTH_DELAY_MS ?? '300');
  const unauthDelayMs = Number.isFinite(envUnauthDelay) && envUnauthDelay >= 0 ? envUnauthDelay : 300;

  let rlAttempt = 0;
  let unauthAttempt = 0;
  while (true) {
    try {
      const res = await client.me();
      // If cookies were just set, a brief unauth window can happen; retry a few times.
      if ((res.meta.status === 401 || res.meta.status === 403) && unauthAttempt < unauthAttempts - 1) {
        await sleep(unauthDelayMs);
        unauthAttempt++;
        continue;
      }
      return NextResponse.json(res, { status: res.meta.status });
    } catch (e: any) {
      if (isRateLimitError(e) && rlAttempt < maxAttempts - 1) {
        const hinted = e.retryAfter && e.retryAfter > 0 ? e.retryAfter : 1;
        const waitSecs = Math.min(hinted, maxWaitSecs);
        await sleep(waitSecs * 1000);
        rlAttempt++;
        continue;
      }
      const status = typeof e?.status === 'number' ? e.status : 500;
      return NextResponse.json({ error: e?.message ?? 'failed' }, { status });
    }
  }
}
