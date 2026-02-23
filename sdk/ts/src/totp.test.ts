import { describe, expect, it } from 'vitest';
import { generateTOTPCode } from './totp';

describe('generateTOTPCode', () => {
  it('generates a 6-digit code for valid base32 secret', () => {
    // RFC-compatible base32 secret used for deterministic formatting checks.
    const code = generateTOTPCode('JBSWY3DPEHPK3PXP');
    expect(code).toMatch(/^\d{6}$/);
  });

  it('throws for empty or invalid input', () => {
    expect(() => generateTOTPCode('')).toThrow('TOTP secret must be a non-empty base32 string');
    expect(() => generateTOTPCode(undefined as unknown as string)).toThrow('TOTP secret must be a non-empty base32 string');
  });
});
