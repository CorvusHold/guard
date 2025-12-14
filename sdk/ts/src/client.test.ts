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
    expect(calls[0].input).toBe(`${baseUrl}/api/v1/auth/magic/verify?token=tok-1`);
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
    expect(calls[0].input).toBe(`${baseUrl}/api/v1/auth/sso/workos/portal-link?tenant_id=t-1&organization_id=org_1&intent=sso`);
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

  it('ssoPortalSession posts token payload and returns session data', async () => {
    const { fetchMock, calls } = makeFetchMock([
      mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json' },
        jsonBody: { tenant_id: 't-1', provider_slug: 'oidc-main', portal_token_id: 'pt-1' },
      }),
    ]);

    const client = new GuardClient({ baseUrl, fetchImpl: fetchMock });
    const res = await client.ssoPortalSession('raw-token');
    expect(res.meta.status).toBe(200);
    expect(res.data.tenant_id).toBe('t-1');
    expect(res.data.provider_slug).toBe('oidc-main');
    expect(res.data.portal_token_id).toBe('pt-1');

    expect(calls[0].input).toBe(`${baseUrl}/api/v1/sso/portal/session`);
    expect(calls[0].init?.method).toBe('POST');
    const body = JSON.parse(calls[0].init?.body as string);
    expect(body).toEqual({ token: 'raw-token' });
  });

  it('ssoPortalProvider sends X-Portal-Token header and returns provider', async () => {
    const { fetchMock, calls } = makeFetchMock([
      mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json' },
        jsonBody: {
          id: 'prov-1',
          tenant_id: 't-1',
          name: 'OIDC Main',
          slug: 'oidc-main',
          provider_type: 'oidc',
          enabled: true,
          allow_signup: true,
          trust_email_verified: true,
          domains: ['example.com'],
        },
      }),
    ]);

    const client = new GuardClient({ baseUrl, fetchImpl: fetchMock });
    const res = await client.ssoPortalProvider('raw-token');
    expect(res.meta.status).toBe(200);
    expect(res.data.id).toBe('prov-1');
    expect(res.data.slug).toBe('oidc-main');

    expect(calls[0].input).toBe(`${baseUrl}/api/v1/sso/portal/provider`);
    const hdrs = new Headers(calls[0].init?.headers);
    expect(hdrs.get('X-Portal-Token')).toBe('raw-token');
  });

  describe('parseSsoCallbackTokens', () => {
    it('parses both tokens from query string', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('?access_token=acc-1&refresh_token=ref-1');
      expect(tokens).not.toBeNull();
      expect(tokens?.access_token).toBe('acc-1');
      expect(tokens?.refresh_token).toBe('ref-1');
      expect(storage.getAccessToken()).toBe('acc-1');
      expect(storage.getRefreshToken()).toBe('ref-1');
    });

    it('parses both tokens from fragment', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('#access_token=acc-2&refresh_token=ref-2');
      expect(tokens).not.toBeNull();
      expect(tokens?.access_token).toBe('acc-2');
      expect(tokens?.refresh_token).toBe('ref-2');
      expect(storage.getAccessToken()).toBe('acc-2');
      expect(storage.getRefreshToken()).toBe('ref-2');
    });

    it('parses both tokens from full URL with fragment', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('https://app.example.com/callback#access_token=acc-3&refresh_token=ref-3');
      expect(tokens).not.toBeNull();
      expect(tokens?.access_token).toBe('acc-3');
      expect(tokens?.refresh_token).toBe('ref-3');
    });

    it('parses access token only (refresh token optional)', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('?access_token=acc-only');
      expect(tokens).not.toBeNull();
      expect(tokens?.access_token).toBe('acc-only');
      expect(tokens?.refresh_token).toBeUndefined();
      expect(storage.getAccessToken()).toBe('acc-only');
      // Refresh token should be null (not set)
      expect(storage.getRefreshToken()).toBeNull();
    });

    it('parses access token only from fragment', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('#access_token=acc-frag-only');
      expect(tokens).not.toBeNull();
      expect(tokens?.access_token).toBe('acc-frag-only');
      expect(tokens?.refresh_token).toBeUndefined();
    });

    it('returns null when access token is missing', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('?refresh_token=ref-only');
      expect(tokens).toBeNull();
      expect(storage.getAccessToken()).toBeNull();
    });

    it('returns null when no tokens present', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('?foo=bar');
      expect(tokens).toBeNull();
    });

    it('returns null for empty string', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      const tokens = client.parseSsoCallbackTokens('');
      expect(tokens).toBeNull();
    });

    it('prefers fragment over query params in full URL', () => {
      const storage = new InMemoryStorage();
      const client = new GuardClient({ baseUrl, storage });
      // URL has both query and fragment - fragment should win
      const tokens = client.parseSsoCallbackTokens('https://app.example.com/callback?access_token=query-acc#access_token=frag-acc&refresh_token=frag-ref');
      expect(tokens).not.toBeNull();
      expect(tokens?.access_token).toBe('frag-acc');
      expect(tokens?.refresh_token).toBe('frag-ref');
    });
  });

  describe('OAuth2 Discovery', () => {
    it('getOAuth2Metadata fetches discovery endpoint and returns metadata', async () => {
      const storage = new InMemoryStorage();
      const { fetchMock, calls } = makeFetchMock([
        mockResponse({
          status: 200,
          headers: { 'content-type': 'application/json' },
          jsonBody: {
            issuer: 'https://api.example.com',
            token_endpoint: 'https://api.example.com/api/v1/auth/refresh',
            introspection_endpoint: 'https://api.example.com/api/v1/auth/introspect',
            revocation_endpoint: 'https://api.example.com/api/v1/auth/revoke',
            userinfo_endpoint: 'https://api.example.com/api/v1/auth/me',
            response_types_supported: ['token'],
            grant_types_supported: ['password', 'refresh_token'],
            scopes_supported: ['openid', 'profile', 'email'],
            guard_auth_modes_supported: ['bearer', 'cookie'],
            guard_auth_mode_default: 'bearer',
            guard_version: '1.0.0',
          },
        }),
      ]);

      const client = new GuardClient({ baseUrl, storage, fetchImpl: fetchMock });
      const res = await client.getOAuth2Metadata();

      expect(res.meta.status).toBe(200);
      expect(res.data.issuer).toBe('https://api.example.com');
      expect(res.data.guard_auth_modes_supported).toEqual(['bearer', 'cookie']);
      expect(res.data.guard_auth_mode_default).toBe('bearer');
      expect(res.data.guard_version).toBe('1.0.0');

      // Verify endpoint called
      expect(calls[0].input).toBe(`${baseUrl}/.well-known/oauth-authorization-server`);
      expect(calls[0].init?.method).toBe('GET');
    });

    it('static discover() fetches metadata without creating client instance', async () => {
      const mockMetadata = {
        issuer: 'https://api.example.com',
        token_endpoint: 'https://api.example.com/api/v1/auth/refresh',
        introspection_endpoint: 'https://api.example.com/api/v1/auth/introspect',
        revocation_endpoint: 'https://api.example.com/api/v1/auth/revoke',
        userinfo_endpoint: 'https://api.example.com/api/v1/auth/me',
        response_types_supported: ['token'],
        grant_types_supported: ['password', 'refresh_token', 'urn:guard:params:oauth:grant-type:magic-link', 'urn:guard:params:oauth:grant-type:sso'],
        scopes_supported: ['openid', 'profile', 'email'],
        guard_auth_modes_supported: ['bearer', 'cookie'],
        guard_auth_mode_default: 'cookie',
        guard_version: '1.0.0',
      };

      const mockFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        expect(String(input)).toBe(`${baseUrl}/.well-known/oauth-authorization-server`);
        expect(init?.method).toBe('GET');
        return mockResponse({
          status: 200,
          headers: { 'content-type': 'application/json' },
          jsonBody: mockMetadata,
        });
      };

      const metadata = await GuardClient.discover(baseUrl, mockFetch);

      expect(metadata.issuer).toBe('https://api.example.com');
      expect(metadata.guard_auth_modes_supported).toEqual(['bearer', 'cookie']);
      expect(metadata.guard_auth_mode_default).toBe('cookie');
      expect(metadata.guard_version).toBe('1.0.0');
      expect(metadata.grant_types_supported).toContain('password');
      expect(metadata.grant_types_supported).toContain('urn:guard:params:oauth:grant-type:magic-link');
    });

    it('static discover() throws on non-ok response', async () => {
      const mockFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const response = mockResponse({
          status: 404,
          headers: { 'content-type': 'application/json' },
          jsonBody: { error: 'not found' },
        });
        // Add statusText property
        Object.defineProperty(response, 'statusText', { value: 'Not Found' });
        return response;
      };

      await expect(() => GuardClient.discover(baseUrl, mockFetch)).rejects.toThrow('Discovery failed: 404 Not Found');
    });

    it('can use discovered metadata to auto-configure client', async () => {
      const mockMetadata = {
        issuer: 'https://api.example.com',
        guard_auth_modes_supported: ['bearer', 'cookie'],
        guard_auth_mode_default: 'cookie',
        guard_version: '1.0.0',
      };

      const mockFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith('/.well-known/oauth-authorization-server')) {
          return mockResponse({
            status: 200,
            headers: { 'content-type': 'application/json' },
            jsonBody: mockMetadata,
          });
        }
        // Login request
        return mockResponse({
          status: 200,
          headers: { 'content-type': 'application/json' },
          jsonBody: { access_token: 'acc-1', refresh_token: 'ref-1' },
        });
      };

      // Discover first
      const metadata = await GuardClient.discover(baseUrl, mockFetch);
      expect(metadata.guard_auth_mode_default).toBe('cookie');

      // Then create client with discovered mode
      const client = new GuardClient({
        baseUrl,
        authMode: metadata.guard_auth_mode_default as 'bearer' | 'cookie',
        fetchImpl: mockFetch,
      });

      // Verify client works
      const res = await client.passwordLogin({ email: 'test@example.com', password: 'pw' });
      expect(res.meta.status).toBe(200);
    });
  });
});
