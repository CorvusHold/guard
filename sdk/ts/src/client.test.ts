import { describe, it, expect } from 'vitest';
import { GuardClient } from './client';
import { InMemoryStorage } from './storage/inMemory';

function mockResponse({
  status = 200,
  headers = {},
  jsonBody,
  textBody,
}: {
  status?: number;
  headers?: Record<string, string>;
  jsonBody?: any;
  textBody?: string;
}) {
  const h = new Headers(headers);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: h,
    async json() {
      return jsonBody;
    },
    async text() {
      return textBody ?? '';
    },
    clone() {
      return this as any;
    },
  } as unknown as Response;
}

type FetchCall = { input: string; init?: RequestInit };

function makeFetchMock(sequence: Array<ReturnType<typeof mockResponse>>) {
  const calls: FetchCall[] = [];
  const fetchMock = async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ input: String(input), init });
    const next = sequence.shift();
    if (!next) throw new Error('No more mocked responses');
    return next;
  };
  return { fetchMock, calls } as const;
}

describe('GuardClient', () => {
  const baseUrl = 'https://api.example.com';

  it('logs in (200), persists tokens, adds Authorization on subsequent requests, and sets dynamic x-guard-client', async () => {
    const storage = new InMemoryStorage();
    const { fetchMock, calls } = makeFetchMock([
      // password login 200 with tokens
      mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json', 'x-request-id': 'rid-login' },
        jsonBody: { access_token: 'acc-1', refresh_token: 'ref-1' },
      }),
      // me 200
      mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json' },
        jsonBody: { id: 'user_1', email: 'a@example.com' },
      }),
    ]);

    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock });

    const login = await client.passwordLogin({ email: 'a@example.com', password: 'pw', tenant_id: 't1' });
    expect(login.meta.status).toBe(200);
    expect('access_token' in login.data).toBe(true);
    expect((login.data as any).access_token).toBe('acc-1');
    expect(storage.getAccessToken()).toBe('acc-1');
    expect(storage.getRefreshToken()).toBe('ref-1');

    const me = await client.me();
    expect(me.data.id).toBe('user_1');

    // Assert headers for both calls
    const hdrsLogin = new Headers(calls[0].init?.headers);
    expect(hdrsLogin.get('x-guard-client')).toMatch(/^\bts-sdk\//);
    // No Authorization on first call since no token yet
    expect(hdrsLogin.get('authorization')).toBeNull();

    const hdrsMe = new Headers(calls[1].init?.headers);
    expect(hdrsMe.get('x-guard-client')).toMatch(/^\bts-sdk\//);
    expect(hdrsMe.get('authorization')).toBe('Bearer acc-1');
  });

  it('password login (202) returns challenge and does not persist tokens', async () => {
    const storage = new InMemoryStorage();
    const { fetchMock } = makeFetchMock([
      mockResponse({
        status: 202,
        headers: { 'content-type': 'application/json' },
        jsonBody: { challenge_token: 'ch-1', method: 'totp' },
      }),
    ]);
    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock });
    const res = await client.passwordLogin({ email: 'a@example.com', password: 'pw' });
    expect(res.meta.status).toBe(202);
    expect('challenge_token' in res.data).toBe(true);
    expect((res.data as any).challenge_token).toBe('ch-1');
    expect(storage.getAccessToken()).toBeNull();
    expect(storage.getRefreshToken()).toBeNull();
  });

  it('refresh uses stored refresh token when not provided', async () => {
    const storage = new InMemoryStorage();
    storage.setRefreshToken('ref-1');
    const { fetchMock, calls } = makeFetchMock([
      mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json' },
        jsonBody: { access_token: 'acc-2', refresh_token: 'ref-2' },
      }),
    ]);

    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock });
    const res = await client.refresh();
    expect(res.data.access_token).toBe('acc-2');
    expect(storage.getAccessToken()).toBe('acc-2');
    expect(storage.getRefreshToken()).toBe('ref-2');

    const sentBody = calls[0].init?.body as string;
    expect(JSON.parse(sentBody)).toEqual({ refresh_token: 'ref-1' });
  });

  it('logout clears stored refresh token on 204', async () => {
    const storage = new InMemoryStorage();
    storage.setRefreshToken('ref-1');
    const { fetchMock } = makeFetchMock([
      mockResponse({ status: 204, headers: {} }),
    ]);

    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock });
    const res = await client.logout();
    expect(res.meta.status).toBe(204);
    expect(storage.getRefreshToken()).toBeNull();
  });

  it('magic verify persists tokens', async () => {
    const storage = new InMemoryStorage();
    const { fetchMock, calls } = makeFetchMock([
      mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json' },
        jsonBody: { access_token: 'acc-3', refresh_token: 'ref-3' },
      }),
    ]);

    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock });
    const res = await client.magicVerify({ token: 'tok-1' });
    expect(res.data.access_token).toBe('acc-3');
    expect(storage.getAccessToken()).toBe('acc-3');
    expect(storage.getRefreshToken()).toBe('ref-3');

    // Ensure token is in query string
    expect(calls[0].input).toBe(`${baseUrl}/v1/auth/magic/verify?token=tok-1`);
  });

  it('sso portal link builds query with default tenant, includes intent, parses link, and sends Authorization', async () => {
    const storage = new InMemoryStorage();
    storage.setAccessToken('acc-admin');
    const { fetchMock, calls } = makeFetchMock([
      mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json', 'x-request-id': 'rid-portal' },
        jsonBody: { link: 'https://portal.example.com/org_1?sso' },
      }),
    ]);

    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock, tenantId: 't-1' });
    const res = await client.getSsoOrganizationPortalLink('workos', {
      organization_id: 'org_1',
      intent: 'sso',
    });
    expect(res.meta.status).toBe(200);
    expect(res.data.link).toBe('https://portal.example.com/org_1?sso');

    // URL and headers
    expect(calls[0].input).toBe(`${baseUrl}/v1/auth/sso/workos/portal-link?tenant_id=t-1&organization_id=org_1&intent=sso`);
    const hdrs = new Headers(calls[0].init?.headers);
    expect(hdrs.get('authorization')).toBe('Bearer acc-admin');
  });

  it('sso portal link throws when tenant_id missing', async () => {
    const storage = new InMemoryStorage();
    storage.setAccessToken('acc-admin');
    const { fetchMock } = makeFetchMock([]);
    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock });
    await expect(() => client.getSsoOrganizationPortalLink('workos', { organization_id: 'org_1' } as any)).rejects.toThrow('tenant_id is required');
  });

  it('sso portal link throws when organization_id missing', async () => {
    const storage = new InMemoryStorage();
    storage.setAccessToken('acc-admin');
    const { fetchMock } = makeFetchMock([]);
    const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock, tenantId: 't-1' });
    await expect(() => client.getSsoOrganizationPortalLink('workos', { tenant_id: 't-1' } as any)).rejects.toThrow('organization_id is required');
  });
});
