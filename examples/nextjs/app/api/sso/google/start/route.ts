import { NextRequest, NextResponse } from 'next/server';
import { GuardClient } from '@corvushold/guard-sdk';

export async function GET(req: NextRequest) {
  const base = process.env.GUARD_BASE_URL;
  if (!base) return NextResponse.json({ error: 'GUARD_BASE_URL must be set' }, { status: 500 });

  const tenantId = process.env.GUARD_TENANT_ID;
  const client = new GuardClient({ baseUrl: base, tenantId });

  const redirect_url = req.nextUrl.searchParams.get('redirect_url') || req.nextUrl.origin;
  const state = req.nextUrl.searchParams.get('state') || '';
  const connection_id = req.nextUrl.searchParams.get('connection_id') || '';
  const organization_id = req.nextUrl.searchParams.get('organization_id') || '';

  const res = await client.startSso('google', { redirect_url, state, connection_id, organization_id });
  const loc = res.data.redirect_url;

  try {
    const locUrl = new URL(loc);
    if (locUrl.hostname === new URL(base).hostname && locUrl.pathname.startsWith('/v1/auth/sso/google/callback')) {
      const nextCb = new URL('/api/sso/google/callback', req.nextUrl.origin);
      locUrl.searchParams.forEach((v, k) => nextCb.searchParams.set(k, v));
      return NextResponse.redirect(nextCb.toString(), { status: 302 });
    }
  } catch {}

  return NextResponse.redirect(loc, { status: 302 });
}
