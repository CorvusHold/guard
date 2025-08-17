import { HttpClient, type TransportOptions } from './http/transport';
import type { FetchLike, TenantId, ResponseWrapper } from './types';
import { InMemoryStorage } from './storage/inMemory';
import type { TokenStorage } from './tokens';
import type { RequestInterceptor } from './http/interceptors';
import pkg from '../package.json';

export interface GuardClientOptions {
  baseUrl: string;
  tenantId?: TenantId;
  fetchImpl?: FetchLike;
  storage?: TokenStorage;
  defaultHeaders?: Record<string, string>;
}

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

  private persistTokensFrom(data: any): void {
    try {
      const access = data?.access_token ?? data?.accessToken ?? null;
      const refresh = data?.refresh_token ?? data?.refreshToken ?? null;
      if (access !== undefined) {
        // allow null to clear
        void this.storage.setAccessToken(access);
      }
      if (refresh !== undefined) {
        void this.storage.setRefreshToken(refresh);
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
  async passwordLogin(body: { email: string; password: string; tenant_id?: string }): Promise<ResponseWrapper<any>> {
    const res = await this.request<any>('/v1/auth/password/login', {
      method: 'POST',
      body: JSON.stringify({ ...body, tenant_id: body.tenant_id ?? this.tenantId }),
    });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }

  // Auth: Verify MFA challenge -> tokens
  async mfaVerify(body: any): Promise<ResponseWrapper<any>> {
    const res = await this.request<any>('/v1/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }

  // Auth: Refresh tokens
  async refresh(body?: { refresh_token?: string }): Promise<ResponseWrapper<any>> {
    let refreshToken = body?.refresh_token ?? null;
    if (!refreshToken) refreshToken = (await Promise.resolve(this.storage.getRefreshToken())) ?? null;
    const res = await this.request<any>('/v1/auth/refresh', {
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
  async me(): Promise<ResponseWrapper<any>> {
    return this.request<any>('/v1/auth/me', { method: 'GET' });
  }

  // Auth: Introspect token (from header or body)
  async introspect(body?: { token?: string }): Promise<ResponseWrapper<any>> {
    return this.request<any>('/v1/auth/introspect', {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    });
  }

  // Auth: Magic link send
  async magicSend(body: { tenant_id: string; email: string; redirect_url?: string }): Promise<ResponseWrapper<unknown>> {
    return this.request<unknown>('/v1/auth/magic/send', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  // Auth: Magic verify (token in query preferred)
  async magicVerify(params: { token?: string } = {}, body?: any): Promise<ResponseWrapper<any>> {
    const qs = this.buildQuery(params);
    const res = await this.request<any>(`/v1/auth/magic/verify${qs}`, {
      method: 'GET',
      // Some servers accept body on GET per spec; include if provided
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (res.meta.status === 200) this.persistTokensFrom(res.data);
    return res;
  }
}
