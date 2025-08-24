import { NextRequest, NextResponse } from 'next/server';
import { getClient } from '@/lib/client';

export async function POST(req: NextRequest) {
  const { email, redirect_url } = await req.json();
  if (!email) return NextResponse.json({ error: 'email is required' }, { status: 400 });

  const client = getClient();
  const tenantId = process.env.GUARD_TENANT_ID;
  const res = await client.magicSend({ tenant_id: tenantId as string, email, redirect_url });

  return NextResponse.json(res, { status: res.meta.status });
}
