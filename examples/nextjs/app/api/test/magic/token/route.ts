import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  // Test-only route: behind explicit env flag and not available in production
  if (process.env.NODE_ENV === 'production' || process.env.ENABLE_TEST_ROUTES !== 'true') {
    return NextResponse.json({ error: 'not found' }, { status: 404 });
  }
  const body = await req.json();
  const { email, redirect_url, tenant_id } = body ?? {};
  if (!email) return NextResponse.json({ error: 'email is required' }, { status: 400 });

  const baseUrl = process.env.GUARD_BASE_URL;
  const tenantId = (tenant_id as string | undefined) ?? process.env.GUARD_TENANT_ID;
  if (!baseUrl || !tenantId) {
    return NextResponse.json({ error: 'server not configured' }, { status: 500 });
  }

  try {
    const r = await fetch(`${baseUrl}/v1/auth/magic/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tenant_id: tenantId, email, redirect_url }),
    });
    const j = await r.json();
    if (!r.ok) return NextResponse.json({ error: j.error || 'failed' }, { status: r.status });
    // expected shape: { token: string }
    return NextResponse.json(j, { status: 200 });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || 'failed' }, { status: 500 });
  }
}
