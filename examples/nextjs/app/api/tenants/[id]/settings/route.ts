import { NextRequest, NextResponse } from 'next/server';
import { getClientFromCookies } from '@/lib/client';
import { isRateLimitError } from '@corvushold/guard-sdk';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function getRetryConfig() {
  const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '3');
  const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 3;
  const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '2');
  const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 2;
  return { maxAttempts, maxWaitSecs };
}

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const client = getClientFromCookies(req);
  const { id } = params;
  const { maxAttempts, maxWaitSecs } = getRetryConfig();

  let attempt = 0;
  while (true) {
    try {
      const res = await client.getTenantSettings(id);
      return NextResponse.json(res.data, { status: res.meta.status });
    } catch (e: any) {
      if (isRateLimitError(e) && attempt < maxAttempts - 1) {
        const hinted = e.retryAfter && e.retryAfter > 0 ? e.retryAfter : 1;
        const waitSecs = Math.min(hinted, maxWaitSecs);
        await sleep(waitSecs * 1000);
        attempt++;
        continue;
      }
      const status = typeof e?.status === 'number' ? e.status : 500;
      return NextResponse.json({ error: e?.message || 'failed' }, { status });
    }
  }
}

export async function PUT(req: NextRequest, { params }: { params: { id: string } }) {
  const client = getClientFromCookies(req);
  const { id } = params;
  const { maxAttempts, maxWaitSecs } = getRetryConfig();

  const payload = await req.json().catch(() => ({}));

  let attempt = 0;
  while (true) {
    try {
      const res = await client.updateTenantSettings(id, payload ?? {});
      if (res.meta.status === 204) return new NextResponse(null, { status: 204 });
      return NextResponse.json(res.data ?? {}, { status: res.meta.status });
    } catch (e: any) {
      if (isRateLimitError(e) && attempt < maxAttempts - 1) {
        const hinted = e.retryAfter && e.retryAfter > 0 ? e.retryAfter : 1;
        const waitSecs = Math.min(hinted, maxWaitSecs);
        await sleep(waitSecs * 1000);
        attempt++;
        continue;
      }
      const status = typeof e?.status === 'number' ? e.status : 500;
      return NextResponse.json({ error: e?.message || 'failed' }, { status });
    }
  }
}
