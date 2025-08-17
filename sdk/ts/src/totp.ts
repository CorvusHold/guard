import { authenticator } from 'otplib';

// Generate a 6-digit TOTP code from a base32 secret.
// Defaults: step=30s, digits=6, algorithm=SHA1 (industry standard for TOTP)
export function generateTOTPCode(base32Secret: string): string {
  if (!base32Secret || typeof base32Secret !== 'string') {
    throw new Error('TOTP secret must be a non-empty base32 string');
  }
  return authenticator.generate(base32Secret);
}
