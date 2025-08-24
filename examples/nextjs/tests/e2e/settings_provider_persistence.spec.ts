import { test, expect } from '@playwright/test';
import { loginWithPasswordAndMFA } from '../support/auth';

// Verifies that changing SSO provider and redirect allowlist via UI persists across reloads.
// Skips allowlist revert if the original allowlist was empty (UI avoids sending empty values).
test('settings: provider and allowlist persist via UI', async ({ page, context }) => {
  test.setTimeout(120_000);
  await context.clearCookies();

  const ownerEmail = process.env.OWNER_EMAIL;
  const ownerPassword = process.env.OWNER_PASSWORD;
  const ownerTotp = process.env.OWNER_TOTP_SECRET ?? process.env.TOTP_SECRET;

  if (!ownerEmail || !ownerPassword) {
    test.skip(true, 'OWNER_EMAIL/OWNER_PASSWORD not set; skipping settings persistence test');
  }

  await loginWithPasswordAndMFA(page, { email: ownerEmail, password: ownerPassword, totpSecret: ownerTotp });

  // Navigate to Settings
  await expect(page.getByTestId('link-settings')).toBeVisible();
  await page.getByTestId('link-settings').click();
  await expect(page.getByText('Tenant Settings')).toBeVisible({ timeout: 30000 });

  const providerSelect = page.locator('#sso_provider');
  const allowlistInput = page.locator('#redirect_allowlist');

  const origProvider = await providerSelect.inputValue();
  const origAllowlist = (await allowlistInput.inputValue()) ?? '';

  // Target values
  const targetProvider = 'dev';
  const targetAllowlist = 'http://localhost:3001';

  // Change provider if needed (safe value: dev)
  if (origProvider !== targetProvider) {
    await providerSelect.selectOption(targetProvider);
  }

  // Only change allowlist if original was non-empty to allow proper revert later
  const shouldChangeAllowlist = !!origAllowlist.trim();
  if (shouldChangeAllowlist && origAllowlist.trim() !== targetAllowlist) {
    await allowlistInput.fill(targetAllowlist);
  }

  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Settings saved.')).toBeVisible();

  // Reload settings page to verify persistence
  await page.reload();
  await expect(page.getByText('Tenant Settings')).toBeVisible({ timeout: 30000 });

  await expect(providerSelect).toHaveValue(targetProvider);
  if (shouldChangeAllowlist) {
    await expect(allowlistInput).toHaveValue(targetAllowlist);
  }

  // Revert changes
  if (origProvider !== targetProvider) {
    await providerSelect.selectOption(origProvider || '');
  }
  if (shouldChangeAllowlist && origAllowlist.trim() !== targetAllowlist) {
    await allowlistInput.fill(origAllowlist);
  }
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Settings saved.')).toBeVisible();
});
