import { NextRequest, NextResponse } from 'next/server';
import { getClientFromCookies } from '@/lib/client';

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  const client = getClientFromCookies(req);

  try {
    const res = await client.blockUser(params.id);
    if (res.meta.status === 204) return new NextResponse(null, { status: 204 });
    return NextResponse.json(res.data ?? {}, { status: res.meta.status });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || 'failed' }, { status: 500 });
  }
}
