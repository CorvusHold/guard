import { NextRequest, NextResponse } from 'next/server';

const ACCESS_COOKIE = 'guard_access_token';
const REFRESH_COOKIE = 'guard_refresh_token';

export async function GET(req: NextRequest) {
  const base = process.env.GUARD_BASE_URL;
  if (!base) return NextResponse.json({ error: 'GUARD_BASE_URL must be set' }, { status: 500 });

  const code = req.nextUrl.searchParams.get('code') || '';
  const state = req.nextUrl.searchParams.get('state') || '';
  if (!code) return NextResponse.json({ error: 'code is required' }, { status: 400 });

  const u = new URL('/v1/auth/sso/google/callback', base);
  u.searchParams.set('code', code);
  if (state) u.searchParams.set('state', state);

  const r = await fetch(u.toString(), { method: 'GET' });
  const j = await r.json().catch(() => ({}));

  if (r.ok) {
    const { access_token, refresh_token } = j as any;
    const out = NextResponse.redirect(new URL('/', req.url), { status: 302 });
    if (access_token) out.cookies.set(ACCESS_COOKIE, access_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    if (refresh_token) out.cookies.set(REFRESH_COOKIE, refresh_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    return out;
  }

  return NextResponse.json({ error: j?.error || 'SSO callback failed' }, { status: r.status });
}
