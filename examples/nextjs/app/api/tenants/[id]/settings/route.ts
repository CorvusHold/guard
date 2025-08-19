import { NextRequest, NextResponse } from 'next/server';

function getBase() {
  const baseUrl = process.env.GUARD_BASE_URL;
  if (!baseUrl) throw new Error('GUARD_BASE_URL is not set');
  return baseUrl;
}

function bearerFrom(req: NextRequest): string | null {
  return req.cookies.get('guard_access_token')?.value ?? null;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function getRetryConfig() {
  const envAttempts = Number(process.env.GUARD_RATE_LIMIT_MAX_ATTEMPTS ?? '3');
  const maxAttempts = Number.isFinite(envAttempts) && envAttempts > 0 ? envAttempts : 3;
  const envMax = Number(process.env.GUARD_RATE_LIMIT_MAX_WAIT_SECS ?? '2');
  const maxWaitSecs = Number.isFinite(envMax) && envMax > 0 ? envMax : 2;
  return { maxAttempts, maxWaitSecs };
}

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const token = bearerFrom(req);
  if (!token) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  const baseUrl = getBase();
  const { id } = params;
  const { maxAttempts, maxWaitSecs } = getRetryConfig();

  let attempt = 0;
  while (true) {
    const r = await fetch(`${baseUrl}/v1/tenants/${encodeURIComponent(id)}/settings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (r.status === 429 && attempt < maxAttempts - 1) {
      const retryAfter = r.headers.get('retry-after');
      const hinted = retryAfter ? Number(retryAfter) : 1;
      const waitSecs = Number.isFinite(hinted) && hinted > 0 ? Math.min(hinted, maxWaitSecs) : 1;
      await sleep(waitSecs * 1000);
      attempt++;
      continue;
    }
    const body = await r.json().catch(() => ({}));
    return NextResponse.json(body, { status: r.status });
  }
}

export async function PUT(req: NextRequest, { params }: { params: { id: string } }) {
  const token = bearerFrom(req);
  if (!token) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  const baseUrl = getBase();
  const { id } = params;
  const { maxAttempts, maxWaitSecs } = getRetryConfig();

  const payload = await req.json().catch(() => ({}));

  let attempt = 0;
  while (true) {
    const r = await fetch(`${baseUrl}/v1/tenants/${encodeURIComponent(id)}/settings`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload ?? {}),
    });
    if (r.status === 429 && attempt < maxAttempts - 1) {
      const retryAfter = r.headers.get('retry-after');
      const hinted = retryAfter ? Number(retryAfter) : 1;
      const waitSecs = Number.isFinite(hinted) && hinted > 0 ? Math.min(hinted, maxWaitSecs) : 1;
      await sleep(waitSecs * 1000);
      attempt++;
      continue;
    }
    if (r.status === 204) return new NextResponse(null, { status: 204 });
    const body = await r.json().catch(() => ({}));
    return NextResponse.json(body, { status: r.status });
  }
}
