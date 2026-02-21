import { describe, expect, it, vi } from 'vitest';
import { buildRateLimitError, parseRetryAfter, toHeadersMap } from './rateLimit';
import { isRateLimitError } from './errors';

describe('rateLimit helpers', () => {
  it('parseRetryAfter supports positive seconds', () => {
    const out = parseRetryAfter('5');
    expect(out.seconds).toBe(5);
    expect(out.nextRetryAt).toBeInstanceOf(Date);
  });

  it('parseRetryAfter ignores zero/negative or invalid values', () => {
    expect(parseRetryAfter('0')).toEqual({ seconds: undefined, nextRetryAt: undefined });
    expect(parseRetryAfter('-1')).toEqual({ seconds: undefined, nextRetryAt: undefined });
    expect(parseRetryAfter('not-a-date')).toEqual({});
    expect(parseRetryAfter(undefined)).toEqual({});
  });

  it('parseRetryAfter supports HTTP dates', () => {
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(new Date('2026-01-01T00:00:00Z').getTime());
    const out = parseRetryAfter('Thu, 01 Jan 2026 00:00:10 GMT');
    expect(out.seconds).toBe(10);
    expect(out.nextRetryAt?.toISOString()).toBe('2026-01-01T00:00:10.000Z');
    nowSpy.mockRestore();
  });

  it('toHeadersMap serializes headers into plain object', () => {
    const map = toHeadersMap(
      new Headers({
        'x-request-id': 'rid-1',
        'retry-after': '7',
      }),
    );

    expect(map['x-request-id']).toBe('rid-1');
    expect(map['retry-after']).toBe('7');
  });

  it('buildRateLimitError builds a typed RateLimitError with parsed retry data', () => {
    const err = buildRateLimitError({
      status: 429,
      message: 'Too many requests',
      requestId: 'rid-42',
      headers: new Headers({ 'retry-after': '3', 'x-request-id': 'rid-42' }),
      raw: { error: 'rate limit exceeded' },
    });

    expect(isRateLimitError(err)).toBe(true);
    if (!isRateLimitError(err)) {
      throw new Error('expected RateLimitError');
    }

    expect(err.status).toBe(429);
    expect(err.message).toBe('Too many requests');
    expect(err.requestId).toBe('rid-42');
    expect(err.retryAfter).toBe(3);
    expect(err.nextRetryAt).toBeInstanceOf(Date);
    expect(err.headers?.['x-request-id']).toBe('rid-42');
  });
});
