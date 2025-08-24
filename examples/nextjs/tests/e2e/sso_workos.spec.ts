import { test, expect } from '@playwright/test';

// This test is opt-in. Enable by setting RUN_SSO_E2E=true and ensure the backend
// is configured for WorkOS dev adapter or test SSO in local environment.
const RUN = process.env.RUN_SSO_E2E === 'true';

(RUN ? test : test.skip)('WorkOS SSO (dev adapter) logs in and can access protected', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByTestId('home')).toBeVisible();

  await page.getByTestId('btn-sso-workos').click();

  // After callback, app redirects to '/'
  await page.waitForURL('**/');
  await expect(page.getByTestId('home')).toBeVisible();

  // Going to protected should work if cookies were set
  await page.goto('/protected');
  await expect(page.getByTestId('protected')).toBeVisible();
});
