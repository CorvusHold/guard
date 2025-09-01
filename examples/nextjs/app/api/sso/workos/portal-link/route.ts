import { NextRequest, NextResponse } from 'next/server';
import { getClientFromCookies } from '@/lib/client';

export async function GET(req: NextRequest) {
  const orgId = req.nextUrl.searchParams.get('organization_id') || '';
  const intent = req.nextUrl.searchParams.get('intent') || undefined;

  if (!orgId) {
    return NextResponse.json({ error: 'organization_id is required' }, { status: 400 });
  }

  try {
    const client = getClientFromCookies(req);
    const res = await client.getSsoOrganizationPortalLink('workos', {
      organization_id: orgId,
      intent,
      // tenant_id will default from the GuardClient instance (env GUARD_TENANT_ID)
    });

    if (res.meta.status >= 200 && res.meta.status < 300) {
      return NextResponse.json(res.data, { status: 200 });
    }
    return NextResponse.json({ error: 'failed to generate portal link', meta: res.meta }, { status: res.meta.status });
  } catch (e: any) {
    const msg = e?.message || 'unexpected error';
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
