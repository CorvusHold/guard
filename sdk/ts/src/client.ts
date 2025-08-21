import { HttpClient, type TransportOptions } from './http/transport';
import type { FetchLike, TenantId, ResponseWrapper, SsoProvider } from './types';
import type { components as OpenAPIComponents } from './generated/openapi';
import { InMemoryStorage } from './storage/inMemory';
import type { TokenStorage } from './tokens';
import type { RequestInterceptor } from './http/interceptors';
import pkg from '../package.json';
import { toHeadersMap } from './rateLimit';

export interface GuardClientOptions {
  baseUrl: string;
  tenantId?: TenantId;
  fetchImpl?: FetchLike;
  storage?: TokenStorage;
  defaultHeaders?: Record<string, string>;
}

// OpenAPI component schema aliases
type TokensResp = OpenAPIComponents['schemas']['controller.tokensResp'];
type MfaChallengeResp = OpenAPIComponents['schemas']['controller.mfaChallengeResp'];

// Type guards to help narrow union results in consumers
export function isTokensResp(data: unknown): data is TokensResp {
  const d = data as any;
  return !!d && (typeof d.access_token === 'string' || typeof d.refresh_token === 'string');
}

export function isMfaChallengeResp(data: unknown): data is MfaChallengeResp {
  const d = data as any;
  return !!d && typeof d.challenge_token === 'string';
}
type MfaVerifyReq = OpenAPIComponents['schemas']['controller.mfaVerifyReq'];
type RefreshReq = OpenAPIComponents['schemas']['controller.refreshReq'];
type UserProfile = OpenAPIComponents['schemas']['domain.UserProfile'];
type Introspection = OpenAPIComponents['schemas']['domain.Introspection'];
type MagicSendReq = OpenAPIComponents['schemas']['controller.magicSendReq'];
type MagicVerifyReq = OpenAPIComponents['schemas']['controller.magicVerifyReq'];
type PasswordSignupInput = {
  email: string;
  password: string;
  tenant_id?: string;
  first_name?: string;
  last_name?: string;
};

// SDK-local DTOs (from server controllers)
export interface AdminUser {
  id: string;
  email_verified: boolean;
  is_active: boolean;
  first_name: string;
  last_name: string;
  roles: string[];
  created_at: string; // RFC3339
  updated_at: string; // RFC3339
  last_login_at?: string | null; // RFC3339 | null
}

export interface AdminUsersResp {
  users: AdminUser[];
}

export interface SessionItem {
  id: string;
  revoked: boolean;
  user_agent: string;
  ip: string;
  created_at: string; // RFC3339
  expires_at: string; // RFC3339
}

export interface SessionsListResp {
  sessions: SessionItem[];
}

export interface TenantSettingsResponse {
  sso_provider: string;
  workos_client_id: string;
  workos_client_secret?: string; // masked
  workos_api_key?: string; // masked
  workos_default_connection_id?: string;
  workos_default_organization_id?: string;
  sso_state_ttl: string;
  sso_redirect_allowlist: string;
}

export interface TenantSettingsPutRequest {
  sso_provider?: string | null;
  workos_client_id?: string | null;
  workos_client_secret?: string | null;
  workos_api_key?: string | null;
  workos_default_connection_id?: string | null;
  workos_default_organization_id?: string | null;
  sso_state_ttl?: string | null; // Go validates time.ParseDuration strings
  sso_redirect_allowlist?: string | null; // comma-separated URLs
}

type PasswordLoginInput = { email: string; password: string; tenant_id?: string };

export class GuardClient {
  readonly baseUrl: string;
  private readonly tenantId?: TenantId;
  private readonly storage: TokenStorage;
  private readonly http: HttpClient;

  constructor(opts: GuardClientOptions) {
    this.baseUrl = opts.baseUrl;
    this.tenantId = opts.tenantId;
    this.storage = opts.storage ?? new InMemoryStorage();

    const authHeaderInterceptor: RequestInterceptor = async (input: RequestInfo | URL, init: RequestInit) => {
      const headers = new Headers(init.headers || {});
      // Attach Authorization if present
      const token = await Promise.resolve(this.storage.getAccessToken());
      if (token && !headers.has('authorization')) {
        headers.set('authorization', `Bearer ${token}`);
      }
      return [input, { ...init, headers }];
    };

    const defaultHeaders = { ...(opts.defaultHeaders ?? {}) };
    // Tenancy today is via body/query. Header will be added later when server adopts it.

    const clientHeader = `ts-sdk/${(pkg as any).version ?? '0.0.0'}`;
    this.http = new HttpClient({
      baseUrl: opts.baseUrl,
      fetchImpl: opts.fetchImpl,
      clientHeader,
      defaultHeaders,
      interceptors: { request: [authHeaderInterceptor] },
    } as TransportOptions);
  }

  // Low-level request passthrough (internal usage by methods)
  protected async request<T>(path: string, init: RequestInit): Promise<ResponseWrapper<T>> {
    return this.http.request<T>(path, init);
  }

  private persistTokensFrom(data: unknown): void {
    try {
      if (isTokensResp(data)) {
        const access = data.access_token ?? null;
        const refresh = data.refresh_token ?? null;
        if (access !== undefined) {
          // allow null to clear
          void this.storage.setAccessToken(access);
        }
        if (refresh !== undefined) {
          void this.storage.setRefreshToken(refresh);
        }
      }
    } catch (_) {
      // best-effort; ignore
    }
  }

  private buildQuery(params: Record<string, string | number | boolean | undefined | null>): string {
    const usp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null) continue;
      usp.set(k, String(v));
    }
    const qs = usp.toString();
    return qs ? `?${qs}` : '';
  }

  // Auth: Password login -> returns tokens (200) or MFA challenge (202)
  async passwordLogin(body: PasswordLoginInput): Promise<ResponseWrapper<TokensResp | MfaChallengeResp>> {
    const res = await this.request<TokensResp | MfaChallengeResp>('/v1/auth/password/login', {
      method: 'POST',
      body: JSON.stringify({ ...body, tenant_id: body.tenant_id ?? this.tenantId }),
    });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }

  // Auth: Password signup -> returns tokens (201 Created)
  async passwordSignup(body: PasswordSignupInput): Promise<ResponseWrapper<TokensResp>> {
    const res = await this.request<TokensResp>('/v1/auth/password/signup', {
      method: 'POST',
      body: JSON.stringify({ ...body, tenant_id: body.tenant_id ?? this.tenantId }),
    });
    if (res.meta.status === 200 || res.meta.status === 201) this.persistTokensFrom(res.data);
    return res;
  }

  // Auth: Verify MFA challenge -> tokens
  async mfaVerify(body: MfaVerifyReq): Promise<ResponseWrapper<TokensResp>> {
    const res = await this.request<TokensResp>('/v1/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }

  // Auth: Refresh tokens
  async refresh(body?: Partial<RefreshReq>): Promise<ResponseWrapper<TokensResp>> {
    let refreshToken = body?.refresh_token ?? null;
    if (!refreshToken) refreshToken = (await Promise.resolve(this.storage.getRefreshToken())) ?? null;
    const res = await this.request<TokensResp>('/v1/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }

  // Auth: Logout (revoke refresh token) -> 204
  async logout(body?: { refresh_token?: string | null }): Promise<ResponseWrapper<unknown>> {
    const b = body ?? {};
    const res = await this.request<unknown>('/v1/auth/logout', {
      method: 'POST',
      body: JSON.stringify(b),
    });
    if (res.meta.status === 204) {
      // best-effort: clear stored refresh; leave access to naturally expire
      void this.storage.setRefreshToken(null);
    }
    return res;
  }

  // Auth: Current user profile
  async me(): Promise<ResponseWrapper<UserProfile>> {
    return this.request<UserProfile>('/v1/auth/me', { method: 'GET' });
  }

  // Auth: Introspect token (from header or body)
  async introspect(body?: { token?: string }): Promise<ResponseWrapper<Introspection>> {
    return this.request<Introspection>('/v1/auth/introspect', {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    });
  }

  // Auth: Magic link send
  async magicSend(body: MagicSendReq): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>('/v1/auth/magic/send', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  // Auth: Magic verify (token in query preferred)
  async magicVerify(params: { token?: string } = {}, body?: MagicVerifyReq): Promise<ResponseWrapper<TokensResp>> {
    const qs = this.buildQuery(params);
    const res = await this.request<TokensResp>(`/v1/auth/magic/verify${qs}`, {
      method: 'GET',
      // Some servers accept body on GET per spec; include if provided
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }

  // Admin: List users (requires admin role). tenant_id from client or param.
  async listUsers(params: { tenant_id?: string } = {}): Promise<ResponseWrapper<AdminUsersResp>> {
    const tenant = params.tenant_id ?? this.tenantId;
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<AdminUsersResp>(`/v1/auth/admin/users${qs}`, { method: 'GET' });
  }

  // Admin: Update user names
  async updateUserNames(id: string, body: { first_name?: string; last_name?: string }): Promise<ResponseWrapper<unknown>> {
    const payload: any = {};
    if (typeof body?.first_name === 'string') payload.first_name = body.first_name;
    if (typeof body?.last_name === 'string') payload.last_name = body.last_name;
    return this.request<unknown>(`/v1/auth/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }

  // Admin: Block user
  async blockUser(id: string): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>(`/v1/auth/admin/users/${encodeURIComponent(id)}/block`, { method: 'POST' });
  }

  // Admin: Unblock user
  async unblockUser(id: string): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>(`/v1/auth/admin/users/${encodeURIComponent(id)}/unblock`, { method: 'POST' });
  }

  // Sessions: List sessions. When includeAll=false, filter to active (non-revoked, not expired) client-side to match example app UX.
  async listSessions(options: { includeAll?: boolean } = {}): Promise<ResponseWrapper<SessionsListResp>> {
    const res = await this.request<SessionsListResp>('/v1/auth/sessions', { method: 'GET', cache: 'no-store' as any });
    if (res.meta.status >= 200 && res.meta.status < 300) {
      const includeAll = !!options.includeAll;
      const sessions = Array.isArray(res.data?.sessions) ? res.data.sessions : [];
      if (!includeAll) {
        const now = Date.now();
        const active = sessions.filter((s: SessionItem) => {
          const revoked = !!s.revoked;
          const expMs = s.expires_at ? Date.parse(s.expires_at) : 0;
          return !revoked && expMs > now;
        });
        return { data: { sessions: active }, meta: res.meta };
      }
    }
    return res;
  }

  // Sessions: Revoke session
  async revokeSession(id: string): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>(`/v1/auth/sessions/${encodeURIComponent(id)}/revoke`, { method: 'POST' });
  }

  // Tenants: Get settings
  async getTenantSettings(tenantId?: string): Promise<ResponseWrapper<TenantSettingsResponse>> {
    const id = tenantId ?? this.tenantId;
    if (!id) throw new Error('tenantId is required');
    return this.request<TenantSettingsResponse>(`/v1/tenants/${encodeURIComponent(id)}/settings`, { method: 'GET' });
  }

  // Tenants: Update settings
  async updateTenantSettings(tenantId: string, settings: TenantSettingsPutRequest): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>(`/v1/tenants/${encodeURIComponent(tenantId)}/settings`, {
      method: 'PUT',
      body: JSON.stringify(settings ?? {}),
    });
  }

  // SSO: Start flow -> returns redirect URL (Location header) without following redirects
  async startSso(provider: SsoProvider, params: {
    tenant_id?: string;
    redirect_url?: string;
    state?: string;
    connection_id?: string;
    organization_id?: string;
  } = {}): Promise<ResponseWrapper<{ redirect_url: string }>> {
    const tenant = params.tenant_id ?? this.tenantId;
    const qs = this.buildQuery({
      tenant_id: tenant,
      redirect_url: params.redirect_url,
      state: params.state,
      connection_id: params.connection_id,
      organization_id: params.organization_id,
    });
    const res = await this.http.requestRaw(`/v1/auth/sso/${provider}/start${qs}`, { method: 'GET', redirect: 'manual' });
    const loc = res.headers.get('location');
    const requestId = res.headers.get('x-request-id') || undefined;
    if (!loc) throw new Error('missing redirect location from SSO start');
    return {
      data: { redirect_url: loc },
      meta: { status: res.status, requestId, headers: toHeadersMap(res.headers) },
    };
  }

  // SSO: Handle callback -> persists tokens on success
  async handleSsoCallback(provider: SsoProvider, params: { code: string; state?: string; email?: string } = { code: '' }): Promise<ResponseWrapper<TokensResp>> {
    const qs = this.buildQuery({ code: params.code, state: params.state, email: params.email });
    const res = await this.request<TokensResp>(`/v1/auth/sso/${provider}/callback${qs}`, { method: 'GET' });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }
}
