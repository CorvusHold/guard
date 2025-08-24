import { test, expect } from '@playwright/test';

// Visiting /protected without cookies should redirect to home due to middleware
// ensuring 'guard_access_token' is present.
test('unauthenticated user is redirected from /protected to /', async ({ page }) => {
  await page.context().clearCookies();
  await page.goto('/protected');
  await page.waitForURL('**/');
  await expect(page.getByTestId('home')).toBeVisible();
});
