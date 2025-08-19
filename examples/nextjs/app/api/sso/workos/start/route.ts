import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const base = process.env.GUARD_BASE_URL;
  const tenant = process.env.GUARD_TENANT_ID;
  if (!base || !tenant) {
    return NextResponse.json({ error: 'GUARD_BASE_URL and GUARD_TENANT_ID must be set' }, { status: 500 });
  }

  // Always point redirect_url to our Next.js callback so we can set cookies client-side
  const nextCallback = new URL('/api/sso/workos/callback', req.nextUrl.origin).toString();
  const state = req.nextUrl.searchParams.get('state') || '';
  const connectionId = req.nextUrl.searchParams.get('connection_id') || '';
  const organizationId = req.nextUrl.searchParams.get('organization_id') || '';

  const u = new URL('/v1/auth/sso/workos/start', base);
  u.searchParams.set('tenant_id', tenant);
  // Force backend to use our callback URL for WorkOS redirect_uri
  u.searchParams.set('redirect_url', nextCallback);
  if (state) u.searchParams.set('state', state);
  if (connectionId) u.searchParams.set('connection_id', connectionId);
  if (organizationId) u.searchParams.set('organization_id', organizationId);

  // Call Guard start with manual redirect handling so we can intercept dev adapter callback URLs.
  const r = await fetch(u.toString(), { method: 'GET', redirect: 'manual' as RequestRedirect });
  const loc = r.headers.get('location');
  if (!loc) {
    return NextResponse.json({ error: 'missing redirect location from SSO start' }, { status: 400 });
  }

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
