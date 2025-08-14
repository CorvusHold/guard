import { describe, it, expect } from 'vitest';
import { HttpClient } from './transport';
import { isRateLimitError } from '../errors';

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
  const body = jsonBody ?? textBody ?? null;
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
      // very small clone since our methods above don't consume any stream
      return this;
    },
  } as unknown as Response;
}

describe('HttpClient', () => {
  it('wraps success JSON and meta including requestId and headers', async () => {
    const calls: any[] = [];
    const fetchMock = async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input: String(input), init });
      return mockResponse({
        status: 200,
        headers: { 'content-type': 'application/json', 'x-request-id': 'rid-123' },
        jsonBody: { ok: true },
      });
    };

    const http = new HttpClient({ baseUrl: 'https://api.example.com', fetchImpl: fetchMock, clientHeader: 'ts-sdk/test' });
    const res = await http.request<{ ok: boolean }>('/hello', { method: 'GET' });

    expect(calls[0].input).toBe('https://api.example.com/hello');
    const hdrs = new Headers(calls[0].init?.headers);
    expect(hdrs.get('x-guard-client')).toBe('ts-sdk/test');
    expect(res.data.ok).toBe(true);
    expect(res.meta.status).toBe(200);
    expect(res.meta.requestId).toBe('rid-123');
    expect(res.meta.headers?.['x-request-id']).toBe('rid-123');
  });

  it('throws RateLimitError with retry-after parsing', async () => {
    const fetchMock = async () =>
      mockResponse({
        status: 429,
        headers: { 'retry-after': '5', 'content-type': 'application/json' },
        jsonBody: { message: 'Too many' },
      });

    const http = new HttpClient({ baseUrl: 'https://api.example.com', fetchImpl: fetchMock });
    await expect(http.request('/hello', { method: 'GET' })).rejects.toSatisfy((err: unknown) => {
      if (!isRateLimitError(err)) return false;
      expect(err.retryAfter).toBe(5);
      expect(err.nextRetryAt).toBeInstanceOf(Date);
      return true;
    });
  });
});
