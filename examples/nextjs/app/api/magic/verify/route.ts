import { NextRequest, NextResponse } from 'next/server';
import { getClient } from '@/lib/client';

const ACCESS_COOKIE = 'guard_access_token';
const REFRESH_COOKIE = 'guard_refresh_token';

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get('token') ?? undefined;
  if (!token) return NextResponse.json({ error: 'token is required' }, { status: 400 });

  const client = getClient();
  const res = await client.magicVerify({ token });

  if (res.meta.status === 200) {
    const { access_token, refresh_token } = res.data as any;
    const out = NextResponse.json({ ok: true }, { status: 200 });
    if (access_token) out.cookies.set(ACCESS_COOKIE, access_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    if (refresh_token) out.cookies.set(REFRESH_COOKIE, refresh_token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false });
    return out;
  }

  const errMsg = (res as any)?.error || 'Magic verify failed';
  return NextResponse.json({ error: errMsg }, { status: res.meta.status });
}
