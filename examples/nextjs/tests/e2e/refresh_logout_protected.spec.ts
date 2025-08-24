import { test, expect } from '@playwright/test';
import { loginWithPasswordAndMFA } from '../support/auth';

// Verifies token refresh using refresh cookie after losing access cookie,
// checks protected route access, and verifies logout clears cookies and blocks protected.
test('refresh tokens, access protected, then logout blocks protected', async ({ page, context, baseURL }) => {
  // Allow more time in case the server performs backoff on 429
  test.setTimeout(120_000);
  if (!baseURL) throw new Error('baseURL missing');

  // Login first
  await loginWithPasswordAndMFA(page);

  // Protected page should be accessible
  await page.goto('/protected');
  await expect(page.getByTestId('protected')).toBeVisible();

  // Simulate expired/lost access token: keep only refresh cookie
  const cookies = await context.cookies(baseURL);
  const refresh = cookies.find(c => c.name === 'guard_refresh_token');
  await context.clearCookies();
  if (refresh) {
    await context.addCookies([refresh]);
  }
  // Give the browser a moment to apply the updated cookie jar
  await page.waitForTimeout(150);

  // Attempt to access protected should redirect to home (middleware sees no access cookie)
  // Avoid extra /api/me calls from the home page while we validate refresh to reduce rate limit contention.
  await page.route('**/api/me', route => route.fulfill({ status: 204, contentType: 'application/json', body: JSON.stringify({ meta: { status: 204 } }) }));
  await page.goto('/protected');
  await page.waitForURL('**/');
  await expect(page.getByTestId('home')).toBeVisible();

  // UI may not show refresh button when not authenticated. Call the API directly.
  // Give the rate limiter a moment to cool down before attempting refresh.
  await page.waitForTimeout(2000);
  const res = await page.evaluate(async () => {
    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
    let last = { ok: false, status: 0 };
    for (let i = 0; i < 5; i++) {
      const r = await fetch('/api/refresh', { method: 'POST', cache: 'no-store' });
      last = { ok: r.ok, status: r.status };
      if (r.ok) break;
      // Retry if transient 401/429
      if (r.status === 401 || r.status === 429) await sleep(500);
      else break;
    }
    return last;
  });
  expect(res.ok, `refresh failed with status ${res.status}`).toBeTruthy();

  // Re-enable /api/me traffic
  await page.unroute('**/api/me');

  // Now protected should be accessible again
  await page.goto('/protected');
  await expect(page.getByTestId('protected')).toBeVisible();

  // Logout and verify protected is blocked
  await page.getByTestId('btn-logout').click();
  // Wait for client-side handler to complete (redirects to home)
  await page.waitForURL('**/');
  await page.waitForLoadState('domcontentloaded');
  const afterLogout = await context.cookies(baseURL);
  expect(afterLogout.find(c => c.name === 'guard_access_token')).toBeFalsy();
  expect(afterLogout.find(c => c.name === 'guard_refresh_token')).toBeFalsy();

  await page.goto('/protected');
  await page.waitForURL('**/');
  await expect(page.getByTestId('home')).toBeVisible();
});
