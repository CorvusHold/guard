import { test, expect } from '@playwright/test';

const UI_BASE = 'http://localhost:4173';

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers,
  };
}

test.describe('Cookie auth mode: guard + logout', () => {
  test.beforeEach(async ({ page, context }) => {
    page.on('console', (msg) => {
      const loc = msg.location();
      console.log(`PAGE CONSOLE [${msg.type()}]`, msg.text(), loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : '');
    });
    page.on('pageerror', (err) => console.log('PAGE ERROR', err?.message || String(err)));
    page.on('close', () => console.log('PAGE CLOSED'));
    // @ts-ignore crash may not exist on all browsers
    page.on('crash', () => console.log('PAGE CRASH'));
    context.on('close', () => console.log('CONTEXT CLOSED'));
    page.on('request', (req) => { if (req.url().includes('/v1/')) console.log('REQ', req.method(), req.url()); });
    page.on('response', async (res) => { if (res.url().includes('/v1/')) console.log('RES', res.status(), res.url()); });
  });

  test('unauthenticated in cookie mode redirects /admin -> /', async ({ page }) => {
    // RequireAuth and/or AdminSettings will call /v1/auth/me in cookie mode
    await page.route('**/v1/auth/me', async (route) => {
      const req = route.request();
      if (req.method() === 'OPTIONS') {
        return route.fulfill({ status: 204, headers: cors({ 'access-control-allow-methods': 'GET,OPTIONS', 'access-control-allow-headers': 'content-type,authorization,accept,x-guard-client' }) });
      }
      return route.fulfill({ status: 401, body: JSON.stringify({ message: 'unauthorized' }), headers: cors({ 'content-type': 'application/json' }) });
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&auth-mode=cookie&source=test`, { waitUntil: 'domcontentloaded' });
    // Expect redirect to login screen
    await expect(page).toHaveURL(/\/+$/);
  });

  test('logout in cookie mode calls API and redirects home', async ({ page }, testInfo) => {
    // First me() should succeed to allow page to render
    await page.route('**/v1/auth/me', async (route) => {
      const req = route.request();
      if (req.method() === 'OPTIONS') {
        return route.fulfill({ status: 204, headers: cors({ 'access-control-allow-methods': 'GET,OPTIONS', 'access-control-allow-headers': 'content-type,authorization,accept,x-guard-client' }) });
      }
      return route.fulfill({ status: 200, body: JSON.stringify({ id: 'user_1', email: 'admin@example.com' }), headers: cors({ 'content-type': 'application/json' }) });
    });

    // Intercept logout to ensure it's called
    let logoutCalled = false;
    await page.route('**/v1/auth/logout', async (route) => {
      const req = route.request();
      if (req.method() === 'OPTIONS') {
        return route.fulfill({ status: 204, headers: cors({ 'access-control-allow-methods': 'POST,OPTIONS', 'access-control-allow-headers': 'content-type,authorization,accept,x-guard-client' }) });
      }
      logoutCalled = true;
      return route.fulfill({ status: 204, body: '', headers: cors({}) });
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&auth-mode=cookie&source=test`, { waitUntil: 'domcontentloaded' });

    // Page should render the header and logout button
    await expect(page.getByRole('heading', { name: 'Admin Settings' })).toBeVisible({ timeout: 10000 }).catch(async (err) => {
      try { await page.screenshot({ path: testInfo.outputPath('cookie-admin-timeout.png'), fullPage: true }); } catch {}
      throw err;
    });
    await expect(page.getByTestId('admin-logout')).toBeVisible();

    await page.getByTestId('admin-logout').click();

    // Ensure we navigated back to home and API was called
    await expect(page).toHaveURL(/\/+$/);
    expect(logoutCalled).toBeTruthy();
  });
});
