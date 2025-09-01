import { NextRequest, NextResponse } from 'next/server';
import { GuardClient, isTokensResp } from '@corvushold/guard-sdk';

const ACCESS_COOKIE = 'guard_access_token';
const REFRESH_COOKIE = 'guard_refresh_token';

export async function GET(req: NextRequest) {
  const base = process.env.GUARD_BASE_URL;
  if (!base) return NextResponse.json({ error: 'GUARD_BASE_URL must be set' }, { status: 500 });

  const code = req.nextUrl.searchParams.get('code') || '';
  const state = req.nextUrl.searchParams.get('state') || '';
  const email = req.nextUrl.searchParams.get('email') || '';
  if (!code) return NextResponse.json({ error: 'code is required' }, { status: 400 });

  const tenantId = process.env.GUARD_TENANT_ID;
  const client = new GuardClient({ baseUrl: base, tenantId });
  const res = await client.handleSsoCallback('workos', { code, state, email });

  if (res.meta.status >= 200 && res.meta.status < 300 && isTokensResp(res.data)) {
    const { access_token, refresh_token } = res.data;
    const out = NextResponse.redirect(new URL('/', req.url), { status: 302 });
    if (access_token) out.cookies.set(ACCESS_COOKIE, access_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    if (refresh_token) out.cookies.set(REFRESH_COOKIE, refresh_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    return out;
  }

  return NextResponse.json({ error: 'SSO callback failed' }, { status: res.meta.status });
}