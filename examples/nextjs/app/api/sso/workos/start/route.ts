import { NextRequest, NextResponse } from 'next/server';
import { GuardClient } from '@corvushold/guard-sdk';

export async function GET(req: NextRequest) {
  const base = process.env.GUARD_BASE_URL;
  if (!base) return NextResponse.json({ error: 'GUARD_BASE_URL must be set' }, { status: 500 });

  const tenantId = process.env.GUARD_TENANT_ID;
  const client = new GuardClient({ baseUrl: base, tenantId });

  // Always point redirect_url to our Next.js callback so we can set cookies client-side
  const redirect_url = new URL('/api/sso/workos/callback', req.nextUrl.origin).toString();
  const state = req.nextUrl.searchParams.get('state') || '';
  const connection_id = req.nextUrl.searchParams.get('connection_id') || '';
  const organization_id = req.nextUrl.searchParams.get('organization_id') || '';

  const res = await client.startSso('workos', { redirect_url, state, connection_id, organization_id });
  const loc = res.data.redirect_url;

  try {
    const locUrl = new URL(loc);
    // If this is a Guard callback URL (dev adapter), rewrite to our Next callback to set cookies client-side.
    if (locUrl.hostname === new URL(base).hostname && locUrl.pathname.startsWith('/v1/auth/sso/workos/callback')) {
      const nextCb = new URL('/api/sso/workos/callback', req.nextUrl.origin);
      // preserve query params (code, state, email if present)
      locUrl.searchParams.forEach((v, k) => nextCb.searchParams.set(k, v));
      return NextResponse.redirect(nextCb.toString(), { status: 302 });
    }
  } catch {
    // fallthrough to redirect to loc as-is
  }
  // Otherwise redirect to provider authorization URL directly
  return NextResponse.redirect(loc, { status: 302 });
}
