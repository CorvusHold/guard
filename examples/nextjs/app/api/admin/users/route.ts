import { NextRequest, NextResponse } from 'next/server';
import { getClientFromCookies } from '@/lib/client';
import { isRateLimitError } from '@corvushold/guard-sdk';

export async function GET(req: NextRequest) {
  const tenantId = process.env.GUARD_TENANT_ID;
  if (!tenantId) return NextResponse.json({ error: 'GUARD_TENANT_ID is not set' }, { status: 500 });

  const client = getClientFromCookies(req);

  try {
    const res = await client.listUsers({ tenant_id: tenantId });
    return NextResponse.json(res.data, { status: res.meta.status });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || 'failed' }, { status: 500 });
  }
}

// Admin create user (invite) - uses backend signup but DOES NOT set cookies
export async function POST(req: NextRequest) {
  const tenantId = process.env.GUARD_TENANT_ID;
  if (!tenantId) return NextResponse.json({ error: 'GUARD_TENANT_ID is not set' }, { status: 500 });

  const client = getClientFromCookies(req);

  // Ensure caller is admin in current tenant
  try {
    const me = await client.me();
    const roles: string[] = Array.isArray(me?.data?.roles) ? me.data.roles : [];
    const isAdmin = roles.some((r) => typeof r === 'string' && r.toLowerCase() === 'admin');
    if (!isAdmin) return NextResponse.json({ error: 'forbidden' }, { status: 403 });
  } catch {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 });
  }

  const { email, password, first_name, last_name } = await req.json();
  if (!email || !password) {
    return NextResponse.json({ error: 'email and password are required' }, { status: 400 });
  }

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '3');
  const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 3;
  const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '2');
  const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 2;

  let attempt = 0;
  while (true) {
    try {
      const res = await client.passwordSignup({ tenant_id: tenantId, email, password, first_name, last_name });
      if (res.meta.status === 200 || res.meta.status === 201) {
        // Do not set cookies here; just indicate success
        return NextResponse.json({ ok: true }, { status: 201 });
      }
      return NextResponse.json(res.data ?? {}, { status: res.meta.status });
    } catch (e: any) {
      if (isRateLimitError(e) && attempt < maxAttempts - 1) {
        const hinted = e.retryAfter && e.retryAfter > 0 ? e.retryAfter : 1;
        const waitSecs = Math.min(hinted, maxWaitSecs);
        await sleep(waitSecs * 1000);
        attempt++;
        continue;
      }
      const msg = e?.message || 'Create user failed';
      return NextResponse.json({ error: msg }, { status: 500 });
    }
  }
}

