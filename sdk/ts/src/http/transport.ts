import { ApiError } from '../errors';
import { buildRateLimitError, toHeadersMap } from '../rateLimit';
import type { FetchLike, ResponseWrapper } from '../types';
import { applyRequestInterceptors, applyResponseInterceptors, type Interceptors } from './interceptors';

export interface TransportOptions {
  baseUrl: string;
  fetchImpl?: FetchLike;
  interceptors?: Interceptors;
  clientHeader?: string; // e.g., "ts-sdk/<version>"
  defaultHeaders?: Record<string, string>;
}

export class HttpClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly interceptors?: Interceptors;
  private readonly clientHeader?: string;
  private readonly defaultHeaders: Record<string, string>;

  constructor(opts: TransportOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
    if (!this.fetchImpl) throw new Error('No fetch implementation provided and global fetch is unavailable');
    this.interceptors = opts.interceptors;
    this.clientHeader = opts.clientHeader ?? 'ts-sdk';
    this.defaultHeaders = { ...(opts.defaultHeaders ?? {}) };
  }

  private buildUrl(path: string): string {
    if (/^https?:\/\//i.test(path)) return path;
    if (!path.startsWith('/')) path = `/${path}`;
    return `${this.baseUrl}${path}`;
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<ResponseWrapper<T>> {
    const url = this.buildUrl(path);

    const headers = new Headers(init.headers || {});
    // default JSON
    if (!headers.has('content-type')) headers.set('content-type', 'application/json');
    if (!headers.has('accept')) headers.set('accept', 'application/json');
    // client identification
    if (this.clientHeader && !headers.has('x-guard-client')) {
      headers.set('x-guard-client', this.clientHeader);
    }
    // default headers
    for (const [k, v] of Object.entries(this.defaultHeaders)) {
      if (!headers.has(k)) headers.set(k, v);
    }

    const reqInit: RequestInit = { ...init, headers };
    const [finalUrl, finalInit] = await applyRequestInterceptors(url, reqInit, this.interceptors?.request as any);

    const res = await this.fetchImpl(finalUrl, finalInit);
    const res2 = await applyResponseInterceptors(res, this.interceptors?.response);

    const requestId = res2.headers.get('x-request-id') || undefined;
    const status = res2.status;

    if (!res2.ok) {
      let body: any = undefined;
      try {
        const ct = res2.headers.get('content-type') || '';
        if (ct.includes('application/json')) body = await res2.clone().json();
        else body = await res2.clone().text();
      } catch {}

      if (status === 429) {
        throw buildRateLimitError({ status, message: (body && body.message) || 'Too Many Requests', requestId, headers: res2.headers, raw: body });
      }

      throw new ApiError({
        status,
        message: (body && body.message) || res2.statusText || `HTTP ${status}`,
        code: body && body.code ? String(body.code) : undefined,
        requestId,
        headers: toHeadersMap(res2.headers),
        raw: body,
      });
    }

    let data: any = undefined;
    const ct = res2.headers.get('content-type') || '';
    if (status !== 204) {
      if (ct.includes('application/json')) data = await res2.json();
      else data = await res2.text();
    }

    return {
      data: data as T,
      meta: { status, requestId, headers: toHeadersMap(res2.headers) },
    };
  }
}
