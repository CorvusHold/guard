import { test, expect } from '@playwright/test';
import { loginWithPasswordAndMFA } from '../support/auth';

// Verifies password login path including MFA when required
// Requires EMAIL/PASSWORD and optionally TOTP_SECRET (when MFA is enabled for the user)
test('password login with MFA (if required) shows profile', async ({ page, context }) => {
  // Ensure a clean state
  await context.clearCookies();

  await loginWithPasswordAndMFA(page);

  // Profile should now be visible
  await expect(page.getByTestId('profile-json')).toBeVisible();
});
