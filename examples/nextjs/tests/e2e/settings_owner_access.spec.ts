import { test, expect } from '@playwright/test';
import { loginWithPasswordAndMFA } from '../support/auth';

// Owner should access /settings and be able to save changes
 test('owner can access settings and save', async ({ page, context }) => {
  test.setTimeout(120_000);
  await context.clearCookies();

  const ownerEmail = process.env.OWNER_EMAIL;
  const ownerPassword = process.env.OWNER_PASSWORD;
  const ownerTotp = process.env.OWNER_TOTP_SECRET ?? process.env.TOTP_SECRET;

  if (!ownerEmail || !ownerPassword) {
    test.skip(true, 'OWNER_EMAIL/OWNER_PASSWORD not set; skipping owner settings test');
  }

  await loginWithPasswordAndMFA(page, { email: ownerEmail, password: ownerPassword, totpSecret: ownerTotp });

  // Owner should see Settings link on home
  await expect(page.getByTestId('link-settings')).toBeVisible();
  await page.getByTestId('link-settings').click();

  // Settings page should be visible
  await expect(page.getByText('Tenant Settings')).toBeVisible({ timeout: 30000 });

  // Change only a safe field (TTL) to avoid breaking flows; do not modify provider or secrets
  const ttlInput = page.locator('#sso_state_ttl');
  await ttlInput.fill('15m');

  // Save
  await page.getByRole('button', { name: 'Save' }).click();

  // Expect success indicator
  await expect(page.getByText('Settings saved.')).toBeVisible();
});
