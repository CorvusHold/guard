import type { HeadersMap } from './types';

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly raw?: unknown;
  readonly headers?: HeadersMap;

  constructor(params: { status: number; message?: string; code?: string; requestId?: string; raw?: unknown; headers?: HeadersMap }) {
    super(params.message || `HTTP ${params.status}`);
    this.name = 'ApiError';
    this.status = params.status;
    this.code = params.code;
    this.requestId = params.requestId;
    this.raw = params.raw;
    this.headers = params.headers;
  }
}

export class RateLimitError extends ApiError {
  readonly retryAfter?: number; // seconds
  readonly nextRetryAt?: Date;

  constructor(params: {
    status: number;
    message?: string;
    code?: string;
    requestId?: string;
    raw?: unknown;
    headers?: HeadersMap;
    retryAfter?: number;
    nextRetryAt?: Date;
  }) {
    super(params);
    this.name = 'RateLimitError';
    this.retryAfter = params.retryAfter;
    this.nextRetryAt = params.nextRetryAt;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

export function isRateLimitError(e: unknown): e is RateLimitError {
  return e instanceof RateLimitError;
}
