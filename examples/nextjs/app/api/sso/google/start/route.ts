import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const base = process.env.GUARD_BASE_URL;
  const tenant = process.env.GUARD_TENANT_ID;
  if (!base || !tenant) {
    return NextResponse.json({ error: 'GUARD_BASE_URL and GUARD_TENANT_ID must be set' }, { status: 500 });
  }

  const redirectUrl = req.nextUrl.searchParams.get('redirect_url') || req.nextUrl.origin;
  const state = req.nextUrl.searchParams.get('state') || '';
  const connection_id = req.nextUrl.searchParams.get('connection_id') || '';
  const organization_id = req.nextUrl.searchParams.get('organization_id') || '';

  const u = new URL('/v1/auth/sso/google/start', base);
  u.searchParams.set('tenant_id', tenant);
  if (redirectUrl) u.searchParams.set('redirect_url', redirectUrl);
  if (state) u.searchParams.set('state', state);
  if (connection_id) u.searchParams.set('connection_id', connection_id);
  if (organization_id) u.searchParams.set('organization_id', organization_id);

  // Manual redirect handling to intercept dev adapter callback
  const r = await fetch(u.toString(), { method: 'GET', redirect: 'manual' as RequestRedirect });
  const loc = r.headers.get('location');
  if (!loc) return NextResponse.json({ error: 'missing redirect location from SSO start' }, { status: 400 });

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
