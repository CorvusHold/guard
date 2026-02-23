import { describe, expect, it } from 'vitest';
import * as sdk from './index';

describe('sdk root index exports', () => {
  it('re-exports key runtime helpers', () => {
    expect(typeof sdk.generateTOTPCode).toBe('function');
    expect(typeof sdk.parseRetryAfter).toBe('function');
    expect(typeof sdk.InMemoryStorage).toBe('function');
    expect(typeof sdk.WebLocalStorage).toBe('function');
  });
});
