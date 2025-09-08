import { test, expect } from '@playwright/test';

const UI_BASE = 'http://localhost:4173';

test.describe('Bearer auth mode: /admin route guard behavior', () => {
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

  test('does not redirect and does not call /v1/auth/me', async ({ page }, testInfo) => {
    let meCalled = false;
    page.on('request', (req) => {
      if (req.url().includes('/v1/auth/me')) meCalled = true;
    });

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&auth-mode=bearer&source=test`,
      { waitUntil: 'domcontentloaded' }
    );

    // Page should render Admin Settings header without redirect
    await expect(page.getByRole('heading', { name: 'Admin Settings' })).toBeVisible({ timeout: 10000 }).catch(async (err) => {
      try { await page.screenshot({ path: testInfo.outputPath('bearer-admin-timeout.png'), fullPage: true }); } catch {}
      throw err;
    });

    // URL should be cleaned (no query params) and remain on /admin
    await expect(page).toHaveURL(new RegExp(`${UI_BASE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/admin/?$`));

    // Ensure no /v1/auth/me call was made in bearer mode
    expect(meCalled).toBeFalsy();
  });
});
