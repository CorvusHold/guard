import { test, expect } from '@playwright/test';

// Verifies user can register via /api/signup and sees profile; Settings link not shown for non-owner
// Uses random email to avoid collisions
 test('signup creates session and shows profile; no Settings link for non-owner', async ({ page, context }) => {
  test.setTimeout(120_000);
  await context.clearCookies();

  const ts = Date.now();
  const email = `e2e+${ts}@example.com`;
  const password = 'P@ssword1!';

  await page.goto('/');
  await page.getByTestId('input-signup-email').fill(email);
  await page.getByTestId('input-signup-password').fill(password);
  await page.getByTestId('input-first-name').fill('E2E');
  await page.getByTestId('input-last-name').fill('User');
  await page.getByTestId('btn-signup').click();

  // After successful signup, profile should be visible
  await expect(page.getByTestId('profile-json')).toBeVisible({ timeout: 30000 });

  // Settings link should not be present for a regular user
  await expect(page.getByTestId('link-settings')).toHaveCount(0);
});
