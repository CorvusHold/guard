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
  authMode?: 'bearer' | 'cookie';
}

// OpenAPI component schema aliases
// Note: The current OpenAPI typings do not expose a dedicated tokens schema,
// so we define the minimal surface we need here and keep other DTOs sourced
// from the generated OpenAPI types.
type TokensResp = {
  access_token?: string | null;
  refresh_token?: string | null;
  success?: boolean;
};
type MfaChallengeResp = OpenAPIComponents['schemas']['controller.mfaChallengeResp'];
type OAuth2MetadataResp = OpenAPIComponents['schemas']['controller.oauth2MetadataResp'];
// Portal link DTO: base on OpenAPI, but enforce `link` is present at type-level for stricter SDK contract
type PortalLink = OpenAPIComponents['schemas']['domain.PortalLink'] & { link: string };

// Portal session DTOs
export interface SsoPortalSessionResp {
  tenant_id: string;
  provider_slug: string;
  portal_token_id: string;
}

export interface SsoPortalContext {
  session: SsoPortalSessionResp;
  provider: SsoProviderItem;
}

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

// RBAC v2 (admin) OpenAPI schema aliases
type RbacPermissionsResp = OpenAPIComponents['schemas']['controller.rbacPermissionsResp'];
type RbacRolesResp = OpenAPIComponents['schemas']['controller.rbacRolesResp'];
type RbacRoleItem = OpenAPIComponents['schemas']['controller.rbacRoleItem'];
type RbacCreateRoleReq = OpenAPIComponents['schemas']['controller.rbacCreateRoleReq'];
type RbacUpdateRoleReq = OpenAPIComponents['schemas']['controller.rbacUpdateRoleReq'];
type RbacRolePermissionReq = OpenAPIComponents['schemas']['controller.rbacRolePermissionReq'];
type RbacUserRolesResp = OpenAPIComponents['schemas']['controller.rbacUserRolesResp'];
type RbacModifyUserRoleReq = OpenAPIComponents['schemas']['controller.rbacModifyUserRoleReq'];
type RbacResolvedPermissionsResp = OpenAPIComponents['schemas']['controller.rbacResolvedPermissionsResp'];

// FGA (admin) DTOs (controller uses snake_case JSON)
export type FgaGroup = {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
};
export type FgaGroupsResp = { groups: FgaGroup[] };
export type FgaAclTuple = {
  id: string;
  tenant_id: string;
  subject_type: string;
  subject_id: string;
  permission_key?: string;
  object_type: string;
  object_id?: string | null;
  created_by?: string | null;
  created_at: string;
};

// Minimal response types for tenant discovery
export interface TenantSummary { id: string; name?: string }
export interface DiscoverTenantsResp { tenants: TenantSummary[] }
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

// SSO Provider Management Types
export type SsoProviderType = 'oidc' | 'saml';

export interface SsoProviderItem {
  id: string;
  tenant_id: string;
  name: string;
  slug: string;
  provider_type: SsoProviderType;
  enabled: boolean;
  allow_signup: boolean;
  trust_email_verified: boolean;
  domains: string[];
  attribute_mapping?: Record<string, any>;

  // OIDC fields
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  client_id?: string;
  client_secret?: string; // masked in responses
  scopes?: string[];
  response_type?: string;
  response_mode?: string;

  // SAML fields
  entity_id?: string;
  acs_url?: string;
  slo_url?: string;
  idp_metadata_url?: string;
  idp_metadata_xml?: string;
  idp_entity_id?: string;
  idp_sso_url?: string;
  idp_slo_url?: string;
  idp_certificate?: string;
  sp_certificate?: string;
  sp_private_key?: string; // masked in responses
  sp_certificate_expires_at?: string;
  want_assertions_signed?: boolean;
  want_response_signed?: boolean;
  sign_requests?: boolean;
  force_authn?: boolean;

  created_at: string;
  updated_at: string;
  created_by?: string;
  updated_by?: string;
}

export interface SsoProvidersListResp {
  providers: SsoProviderItem[];
  total: number;
}

export interface CreateSsoProviderReq {
  tenant_id: string;
  name: string;
  slug: string;
  provider_type: SsoProviderType;
  enabled?: boolean;
  allow_signup?: boolean;
  trust_email_verified?: boolean;
  domains?: string[];
  attribute_mapping?: Record<string, any>;

  // OIDC fields
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  response_type?: string;
  response_mode?: string;

  // SAML fields
  entity_id?: string;
  acs_url?: string;
  slo_url?: string;
  idp_metadata_url?: string;
  idp_metadata_xml?: string;
  idp_entity_id?: string;
  idp_sso_url?: string;
  idp_slo_url?: string;
  idp_certificate?: string;
  sp_certificate?: string;
  sp_private_key?: string;
  want_assertions_signed?: boolean;
  want_response_signed?: boolean;
  sign_requests?: boolean;
  force_authn?: boolean;
}

export interface UpdateSsoProviderReq {
  name?: string;
  enabled?: boolean;
  allow_signup?: boolean;
  trust_email_verified?: boolean;
  domains?: string[];
  attribute_mapping?: Record<string, any>;

  // OIDC fields
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  response_type?: string;
  response_mode?: string;

  // SAML fields
  entity_id?: string;
  acs_url?: string;
  slo_url?: string;
  idp_metadata_url?: string;
  idp_metadata_xml?: string;
  idp_entity_id?: string;
  idp_sso_url?: string;
  idp_slo_url?: string;
  idp_certificate?: string;
  sp_certificate?: string;
  sp_private_key?: string;
  want_assertions_signed?: boolean;
  want_response_signed?: boolean;
  sign_requests?: boolean;
  force_authn?: boolean;
}

export interface SsoTestProviderResp {
  success: boolean;
  metadata?: Record<string, any>;
  error?: string;
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

    const mode = opts.authMode ?? 'bearer';
    const authHeaderInterceptor: RequestInterceptor = async (input: RequestInfo | URL, init: RequestInit) => {
      const headers = new Headers(init.headers || {});
      if (mode === 'bearer') {
        // Attach Authorization if present
        const token = await Promise.resolve(this.storage.getAccessToken());
        if (token && !headers.has('authorization')) {
          headers.set('authorization', `Bearer ${token}`);
        }
      } else if (mode === 'cookie') {
        // Set X-Auth-Mode header to signal cookie mode to backend
        headers.set('X-Auth-Mode', 'cookie');
      }
      return [input, { ...init, headers }];
    };

    const defaultHeaders = { ...(opts.defaultHeaders ?? {}) };
    // Tenancy today is via body/query. Header will be added later when server adopts it.

    const clientHeader = `ts-sdk/${(pkg as any).version ?? '0.0.0'}`;
    // In cookie mode, always include credentials (cookies) with requests.
    // This requires the backend to have proper CORS configuration with Access-Control-Allow-Credentials: true
    let credentialsOpt: RequestCredentials | undefined = undefined;
    if (mode === 'cookie') {
      credentialsOpt = 'include';
    }

    this.http = new HttpClient({
      baseUrl: opts.baseUrl,
      fetchImpl: opts.fetchImpl,
      clientHeader,
      defaultHeaders,
      interceptors: { request: [authHeaderInterceptor] },
      credentials: credentialsOpt,
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

  // Auth: Email discovery (progressive login)
  async emailDiscover(body: { email: string; tenant_id?: string }): Promise<ResponseWrapper<{
    found: boolean;
    has_tenant: boolean;
    tenant_id?: string;
    tenant_name?: string;
    user_exists: boolean;
    suggestions?: string[];
  }>> {
    const headers: Record<string, string> = {};
    const tid = body.tenant_id ?? this.tenantId;
    if (tid) headers['X-Tenant-ID'] = String(tid);
    return this.request(`/v1/auth/email/discover`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ email: body.email })
    });
  }

  // --- MFA self-service ---
  async mfaStartTotp(): Promise<ResponseWrapper<{ secret: string; otpauth_url: string }>> {
    return this.request<{ secret: string; otpauth_url: string }>('/v1/auth/mfa/totp/start', { method: 'POST' });
  }

  async mfaActivateTotp(body: { code: string }): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>('/v1/auth/mfa/totp/activate', { method: 'POST', body: JSON.stringify(body) });
  }

  async mfaDisableTotp(): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>('/v1/auth/mfa/totp/disable', { method: 'POST' });
  }

  async mfaGenerateBackupCodes(body: { count?: number } = {}): Promise<ResponseWrapper<{ codes: string[] }>> {
    return this.request<{ codes: string[] }>('/v1/auth/mfa/backup/generate', { method: 'POST', body: JSON.stringify({ count: body.count ?? 5 }) });
  }

  async mfaCountBackupCodes(): Promise<ResponseWrapper<{ count: number }>> {
    return this.request<{ count: number }>('/v1/auth/mfa/backup/count', { method: 'GET' });
  }

  // Tenants: Discover tenants for a given email (used by login tenant selection)
  async discoverTenants(params: { email: string }): Promise<ResponseWrapper<DiscoverTenantsResp>> {
    const qs = this.buildQuery({ email: params.email });
    return this.request<DiscoverTenantsResp>(`/v1/auth/tenants${qs}`, { method: 'GET' });
  }

  // Tenants: Create
  async createTenant(body: { name: string }): Promise<ResponseWrapper<{ id: string; name: string; is_active?: boolean; created_at?: string; updated_at?: string }>> {
    return this.request(`/tenants`, { method: 'POST', body: JSON.stringify({ name: body.name }) });
  }

  // Tenants: Get by ID
  async getTenant(id: string): Promise<ResponseWrapper<{ id: string; name: string; is_active: boolean; created_at: string; updated_at: string }>> {
    return this.request(`/tenants/${encodeURIComponent(id)}`, { method: 'GET' });
  }

  // Tenants: List (admin)
  async listTenants(params: { q?: string; page?: number; page_size?: number; active?: number | boolean } = {}): Promise<ResponseWrapper<{ items: Array<{ id: string; name: string; is_active: boolean; created_at: string; updated_at: string }>; total: number; page: number; page_size: number; total_pages: number }>> {
    const qs = this.buildQuery({
      q: params.q,
      page: params.page,
      page_size: params.page_size,
      active: typeof params.active === 'boolean' ? (params.active ? 1 : 0) : params.active
    });
    return this.request(`/tenants${qs}`, { method: 'GET' });
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

  // SSO: WorkOS Organization Portal link (admin-only on server)
  async getSsoOrganizationPortalLink(provider: SsoProvider, params: {
    tenant_id?: string;
    organization_id: string;
    intent?: string;
  }): Promise<ResponseWrapper<PortalLink>> {
    const tenant = params.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    if (!params?.organization_id) throw new Error('organization_id is required');
    const qs = this.buildQuery({
      tenant_id: tenant,
      organization_id: params.organization_id,
      intent: params.intent,
    });
    return this.request<PortalLink>(`/v1/auth/sso/${provider}/portal-link${qs}`, { method: 'GET' });
  }

  // SSO: Portal token session exchange (public, portal-token gated)
  async ssoPortalSession(token: string): Promise<ResponseWrapper<SsoPortalSessionResp>> {
    if (!token || typeof token !== 'string') {
      throw new Error('token is required');
    }
    return this.request<SsoPortalSessionResp>('/v1/sso/portal/session', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  // SSO: Portal provider config (public, portal-token gated)
  async ssoPortalProvider(token: string): Promise<ResponseWrapper<SsoProviderItem>> {
    if (!token || typeof token !== 'string') {
      throw new Error('token is required');
    }
    const headers: Record<string, string> = { 'X-Portal-Token': token };
    return this.request<SsoProviderItem>('/v1/sso/portal/provider', {
      method: 'GET',
      headers,
    });
  }

  // High-level helper: load portal session and provider in one call
  async loadSsoPortalContext(token: string): Promise<SsoPortalContext> {
    const sessionRes = await this.ssoPortalSession(token);
    if (sessionRes.meta.status !== 200 || !sessionRes.data) {
      throw new Error(`portal session failed with status ${sessionRes.meta.status}`);
    }

    const providerRes = await this.ssoPortalProvider(token);
    if (providerRes.meta.status !== 200 || !providerRes.data) {
      throw new Error(`portal provider failed with status ${providerRes.meta.status}`);
    }

    return { session: sessionRes.data, provider: providerRes.data };
  }

  // ==============================
  // SSO Provider Management (Admin-only endpoints)
  // ==============================

  // List SSO providers for a tenant
  async ssoListProviders(params: { tenant_id?: string } = {}): Promise<ResponseWrapper<SsoProvidersListResp>> {
    const tenant = params.tenant_id ?? this.tenantId;
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<SsoProvidersListResp>(`/v1/sso/providers${qs}`, { method: 'GET' });
  }

  // Create a new SSO provider
  async ssoCreateProvider(body: CreateSsoProviderReq): Promise<ResponseWrapper<SsoProviderItem>> {
    return this.request<SsoProviderItem>('/v1/sso/providers', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  // Get a specific SSO provider by ID
  async ssoGetProvider(id: string): Promise<ResponseWrapper<SsoProviderItem>> {
    return this.request<SsoProviderItem>(`/v1/sso/providers/${encodeURIComponent(id)}`, {
      method: 'GET',
    });
  }

  // Update an existing SSO provider
  async ssoUpdateProvider(id: string, body: UpdateSsoProviderReq): Promise<ResponseWrapper<SsoProviderItem>> {
    return this.request<SsoProviderItem>(`/v1/sso/providers/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  // Delete an SSO provider
  async ssoDeleteProvider(id: string): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>(`/v1/sso/providers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  // Test SSO provider configuration
  async ssoTestProvider(id: string): Promise<ResponseWrapper<SsoTestProviderResp>> {
    return this.request<SsoTestProviderResp>(`/v1/sso/providers/${encodeURIComponent(id)}/test`, {
      method: 'POST',
    });
  }

  // ==============================
  // RBAC v2 (Admin-only endpoints)
  // ==============================

  // RBAC: List all permissions (admin-only)
  async rbacListPermissions(): Promise<ResponseWrapper<RbacPermissionsResp>> {
    return this.request<RbacPermissionsResp>('/v1/auth/admin/rbac/permissions', { method: 'GET' });
  }

  // RBAC: List roles for a tenant
  async rbacListRoles(params: { tenant_id?: string } = {}): Promise<ResponseWrapper<RbacRolesResp>> {
    const tenant = params.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<RbacRolesResp>(`/v1/auth/admin/rbac/roles${qs}`, { method: 'GET' });
  }

  // RBAC: Create role
  async rbacCreateRole(body: Omit<RbacCreateRoleReq, 'tenant_id'> & { tenant_id?: string }): Promise<ResponseWrapper<RbacRoleItem>> {
    const tenant = body.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const payload: RbacCreateRoleReq = { tenant_id: tenant, name: (body as any).name, description: (body as any).description } as RbacCreateRoleReq;
    return this.request<RbacRoleItem>('/v1/auth/admin/rbac/roles', { method: 'POST', body: JSON.stringify(payload) });
  }

  // RBAC: Update role
  async rbacUpdateRole(id: string, body: Omit<RbacUpdateRoleReq, 'tenant_id'> & { tenant_id?: string }): Promise<ResponseWrapper<RbacRoleItem>> {
    const tenant = body.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const payload: RbacUpdateRoleReq = { tenant_id: tenant, name: (body as any).name, description: (body as any).description } as RbacUpdateRoleReq;
    return this.request<RbacRoleItem>(`/v1/auth/admin/rbac/roles/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(payload) });
  }

  // RBAC: Delete role
  async rbacDeleteRole(id: string, params: { tenant_id?: string } = {}): Promise<ResponseWrapper<unknown>> {
    const tenant = params.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<unknown>(`/v1/auth/admin/rbac/roles/${encodeURIComponent(id)}${qs}`, { method: 'DELETE' });
  }

  // RBAC: List user roles
  async rbacListUserRoles(userId: string, params: { tenant_id?: string } = {}): Promise<ResponseWrapper<RbacUserRolesResp>> {
    const tenant = params.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<RbacUserRolesResp>(`/v1/auth/admin/rbac/users/${encodeURIComponent(userId)}/roles${qs}`, { method: 'GET' });
  }

  // RBAC: Add user role
  async rbacAddUserRole(userId: string, body: Omit<RbacModifyUserRoleReq, 'tenant_id'> & { tenant_id?: string }): Promise<ResponseWrapper<unknown>> {
    const tenant = body.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const payload: RbacModifyUserRoleReq = { tenant_id: tenant, role_id: (body as any).role_id } as RbacModifyUserRoleReq;
    return this.request<unknown>(`/v1/auth/admin/rbac/users/${encodeURIComponent(userId)}/roles`, { method: 'POST', body: JSON.stringify(payload) });
  }

  // RBAC: Remove user role
  async rbacRemoveUserRole(userId: string, body: Omit<RbacModifyUserRoleReq, 'tenant_id'> & { tenant_id?: string }): Promise<ResponseWrapper<unknown>> {
    const tenant = body.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const payload: RbacModifyUserRoleReq = { tenant_id: tenant, role_id: (body as any).role_id } as RbacModifyUserRoleReq;
    return this.request<unknown>(`/v1/auth/admin/rbac/users/${encodeURIComponent(userId)}/roles`, { method: 'DELETE', body: JSON.stringify(payload) });
  }

  // RBAC: Upsert role permission
  async rbacUpsertRolePermission(roleId: string, body: RbacRolePermissionReq): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>(`/v1/auth/admin/rbac/roles/${encodeURIComponent(roleId)}/permissions`, { method: 'POST', body: JSON.stringify(body) });
  }

  // RBAC: Delete role permission
  async rbacDeleteRolePermission(roleId: string, body: RbacRolePermissionReq): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>(`/v1/auth/admin/rbac/roles/${encodeURIComponent(roleId)}/permissions`, { method: 'DELETE', body: JSON.stringify(body) });
  }

  // RBAC: Resolve user permissions
  async rbacResolveUserPermissions(userId: string, params: { tenant_id?: string }): Promise<ResponseWrapper<RbacResolvedPermissionsResp>> {
    const tenant = params?.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<RbacResolvedPermissionsResp>(`/v1/auth/admin/rbac/users/${encodeURIComponent(userId)}/permissions/resolve${qs}`, { method: 'GET' });
  }

  // ==============================
  // FGA (Admin-only endpoints)
  // ==============================

  // Groups: list
  async fgaListGroups(params: { tenant_id?: string }): Promise<ResponseWrapper<FgaGroupsResp>> {
    const tenant = params?.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<FgaGroupsResp>(`/v1/auth/admin/fga/groups${qs}`, { method: 'GET' });
  }

  // Groups: create
  async fgaCreateGroup(body: { tenant_id?: string; name: string; description?: string | null }): Promise<ResponseWrapper<FgaGroup>> {
    const tenant = body?.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const payload = { tenant_id: tenant, name: body.name, description: body?.description ?? null } as any;
    return this.request<FgaGroup>(`/v1/auth/admin/fga/groups`, { method: 'POST', body: JSON.stringify(payload) });
  }

  // Groups: delete
  async fgaDeleteGroup(id: string, params: { tenant_id?: string }): Promise<ResponseWrapper<unknown>> {
    const tenant = params?.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const qs = this.buildQuery({ tenant_id: tenant });
    return this.request<unknown>(`/v1/auth/admin/fga/groups/${encodeURIComponent(id)}${qs}`, { method: 'DELETE' });
  }

  // Group membership: add
  async fgaAddGroupMember(groupId: string, body: { user_id: string }): Promise<ResponseWrapper<unknown>> {
    const payload = { user_id: body.user_id } as any;
    return this.request<unknown>(`/v1/auth/admin/fga/groups/${encodeURIComponent(groupId)}/members`, { method: 'POST', body: JSON.stringify(payload) });
    }

  // Group membership: remove
  async fgaRemoveGroupMember(groupId: string, body: { user_id: string }): Promise<ResponseWrapper<unknown>> {
    const payload = { user_id: body.user_id } as any;
    return this.request<unknown>(`/v1/auth/admin/fga/groups/${encodeURIComponent(groupId)}/members`, { method: 'DELETE', body: JSON.stringify(payload) });
  }

  // ACL tuples: create
  async fgaCreateAclTuple(body: { tenant_id?: string; subject_type: string; subject_id: string; permission_key: string; object_type: string; object_id?: string | null; created_by?: string | null }): Promise<ResponseWrapper<FgaAclTuple>> {
    const tenant = body?.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const payload = { ...body, tenant_id: tenant } as any;
    return this.request<FgaAclTuple>(`/v1/auth/admin/fga/acl/tuples`, { method: 'POST', body: JSON.stringify(payload) });
  }

  // ACL tuples: delete
  async fgaDeleteAclTuple(body: { tenant_id?: string; subject_type: string; subject_id: string; permission_key: string; object_type: string; object_id?: string | null }): Promise<ResponseWrapper<unknown>> {
    const tenant = body?.tenant_id ?? this.tenantId;
    if (!tenant) throw new Error('tenant_id is required');
    const payload = { ...body, tenant_id: tenant } as any;
    return this.request<unknown>(`/v1/auth/admin/fga/acl/tuples`, { method: 'DELETE', body: JSON.stringify(payload) });
  }

  // ==============================
  // OAuth2 Discovery (RFC 8414)
  // ==============================

  /**
   * Fetch OAuth 2.0 Authorization Server Metadata (RFC 8414)
   * Returns server capabilities including supported auth modes, endpoints, and grant types.
   * This endpoint is public and does not require authentication.
   */
  async getOAuth2Metadata(): Promise<ResponseWrapper<OAuth2MetadataResp>> {
    return this.request<OAuth2MetadataResp>('/.well-known/oauth-authorization-server', { method: 'GET' });
  }

  /**
   * Static helper to discover OAuth2 metadata from any Guard API base URL.
   * Useful for auto-configuration before creating a GuardClient instance.
   *
   * @example
   * ```ts
   * const metadata = await GuardClient.discover('https://api.example.com');
   * console.log(metadata.guard_auth_modes_supported); // ['bearer', 'cookie']
   * console.log(metadata.guard_auth_mode_default);    // 'bearer'
   *
   * // Create client with discovered default auth mode
   * const client = new GuardClient({
   *   baseUrl: 'https://api.example.com',
   *   authMode: metadata.guard_auth_mode_default as 'bearer' | 'cookie'
   * });
   * ```
   */
  static async discover(baseUrl: string, fetchImpl?: FetchLike): Promise<OAuth2MetadataResp> {
    const fetch = fetchImpl ?? (typeof window !== 'undefined' ? window.fetch.bind(window) : globalThis.fetch);
    const url = `${baseUrl}/.well-known/oauth-authorization-server`;
    const response = await fetch(url, { method: 'GET' });

    if (!response.ok) {
      throw new Error(`Discovery failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }
}
