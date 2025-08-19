import { test, expect } from '@playwright/test';

// Non-owner users should see Forbidden on the /settings page
 test('non-owner user is forbidden from settings', async ({ page, context }) => {
  test.setTimeout(120_000);
  await context.clearCookies();

  // Create a fresh user via signup
  const ts = Date.now();
  const email = `e2e-forbid+${ts}@example.com`;
  const password = 'P@ssword1!';

  await page.goto('/');
  await page.getByTestId('input-signup-email').fill(email);
  await page.getByTestId('input-signup-password').fill(password);
  await page.getByTestId('input-first-name').fill('E2E');
  await page.getByTestId('input-last-name').fill('User');
  await page.getByTestId('btn-signup').click();

  await expect(page.getByTestId('profile-json')).toBeVisible({ timeout: 60000 });

  // Navigate to settings directly; middleware requires access cookie (present after signup)
  await page.goto('/settings');
  await expect(page.getByText('Forbidden')).toBeVisible();
  await expect(page.getByText('You must be an owner to access Settings.')).toBeVisible();
});
