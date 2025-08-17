import { RateLimitError } from './errors';
import type { HeadersMap } from './types';

export function parseRetryAfter(retryAfter: string | null | undefined): { seconds?: number; nextRetryAt?: Date } {
  if (!retryAfter) return {};
  const trimmed = retryAfter.trim();
  // Retry-After can be either seconds or HTTP date
  const secs = Number(trimmed);
  if (!Number.isNaN(secs)) {
    return { seconds: secs > 0 ? secs : undefined, nextRetryAt: secs > 0 ? new Date(Date.now() + secs * 1000) : undefined };
  }
  const date = new Date(trimmed);
  if (!Number.isNaN(date.getTime())) {
    const ms = date.getTime() - Date.now();
    const seconds = ms > 0 ? Math.ceil(ms / 1000) : undefined;
    return { seconds, nextRetryAt: ms > 0 ? date : undefined };
  }
  return {};
}

export function toHeadersMap(headers: Headers): HeadersMap {
  const obj: HeadersMap = {};
  headers.forEach((v, k) => {
    obj[k] = v;
  });
  return obj;
}

export function buildRateLimitError(args: {
  status: number;
  message?: string;
  requestId?: string;
  headers: Headers;
  raw?: unknown;
}): RateLimitError {
  const { seconds, nextRetryAt } = parseRetryAfter(args.headers.get('retry-after'));
  return new RateLimitError({
    status: args.status,
    message: args.message,
    requestId: args.requestId,
    headers: toHeadersMap(args.headers),
    retryAfter: seconds,
    nextRetryAt,
    raw: args.raw,
  });
}
