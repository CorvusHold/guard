import { NextRequest, NextResponse } from 'next/server';
import { getClientFromCookies } from '@/lib/client';

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  const client = getClientFromCookies(req);

  let body: any = {};
  try { body = await req.json(); } catch {}
  const payload: any = {};
  if (typeof body?.first_name === 'string') payload.first_name = body.first_name;
  if (typeof body?.last_name === 'string') payload.last_name = body.last_name;
  if (!('first_name' in payload) && !('last_name' in payload)) {
    return NextResponse.json({ error: 'first_name or last_name is required' }, { status: 400 });
  }

  try {
    const res = await client.updateUserNames(params.id, payload);
    return NextResponse.json(res.data ?? {}, { status: res.meta.status });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || 'failed' }, { status: 500 });
  }
}
