import { expect, Page } from '@playwright/test';
import { authenticator } from 'otplib';

export async function loginWithPasswordAndMFA(page: Page, opts?: { email?: string; password?: string; totpSecret?: string }) {
  // Prefer NONMFA creds since the example app points GUARD_TENANT_ID to NONMFA_TENANT_ID
  const email = opts?.email ?? process.env.NONMFA_EMAIL ?? process.env.EMAIL ?? '';
  const password = opts?.password ?? process.env.NONMFA_PASSWORD ?? process.env.PASSWORD ?? '';
  const totpSecret = opts?.totpSecret ?? process.env.TOTP_SECRET ?? '';

  if (!email || !password) throw new Error('Missing EMAIL/PASSWORD in environment');

  await page.goto('/');
  // Wait for any relevant UI to appear: login form, MFA form, or profile
  await page.waitForSelector('[data-testid="input-email"], [data-testid="profile-json"], [data-testid="input-mfa-code"]', { timeout: 30000, state: 'attached' });

  // If already logged in
  if (await page.getByTestId('profile-json').isVisible().catch(() => false)) {
    return;
  }

  await page.getByTestId('input-email').fill(email);
  await page.getByTestId('input-password').fill(password);
  await page.getByTestId('btn-login').click();

  // Either profile appears (no MFA) or MFA challenge appears
  const mfaForm = page.getByTestId('btn-verify-mfa');
  const profile = page.getByTestId('profile-json');
  await page.waitForSelector('[data-testid="profile-json"], [data-testid="input-mfa-code"]', { timeout: 30000, state: 'attached' });
  if (await profile.isVisible().catch(() => false)) return;

  // MFA path
  if (!totpSecret) throw new Error('Missing TOTP_SECRET in environment for MFA test');
  const code = authenticator.generate(totpSecret);
  await page.getByTestId('input-mfa-code').fill(code);
  await page.getByTestId('btn-verify-mfa').click();
  await expect(page.getByTestId('profile-json')).toBeVisible({ timeout: 30000 });
}
