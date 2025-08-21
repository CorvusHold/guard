import { NextRequest, NextResponse } from 'next/server';
import { getClientFromCookies } from '@/lib/client';

export async function GET(req: NextRequest) {
  const client = getClientFromCookies(req);
  const allParam = req.nextUrl.searchParams.get('all');
  const includeAll = allParam === '1' || (allParam ?? '').toLowerCase() === 'true';
  if (includeAll) {
    // Only admins/owners can request all sessions (including revoked/expired)
    try {
      const me = await client.me();
      const roles: string[] = Array.isArray(me?.data?.roles) ? me.data.roles : [];
      const allowed = roles.some((r) => typeof r === 'string' && (r.toLowerCase() === 'admin' || r.toLowerCase() === 'owner'));
      if (!allowed) return NextResponse.json({ error: 'forbidden' }, { status: 403 });
    } catch {
      return NextResponse.json({ error: 'forbidden' }, { status: 403 });
    }
  }

  try {
    const res = await client.listSessions({ includeAll });
    if (res.meta.status < 200 || res.meta.status >= 300) {
      return NextResponse.json(res, { status: res.meta.status });
    }
    const sessions = Array.isArray(res?.data?.sessions) ? res.data.sessions : [];
    if (includeAll) {
      return NextResponse.json({ sessions }, { status: res.meta.status });
    }
    const now = Date.now();
    const active = sessions.filter((s: any) => {
      const revoked = !!s?.revoked;
      const expMs = s?.expires_at ? Date.parse(s.expires_at) : 0;
      return !revoked && expMs > now;
    });
    return NextResponse.json({ sessions: active }, { status: res.meta.status });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || 'failed' }, { status: 500 });
  }
}
