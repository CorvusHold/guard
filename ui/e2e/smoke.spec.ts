import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'

test.describe('UI smoke', () => {
  test('admin page renders and stays open', async ({ page }) => {
    // Minimal listeners for diagnostics
    page.on('close', () => console.log('PAGE CLOSED'))
    // @ts-expect-error
    page.on('crash', () => console.log('PAGE CRASH'))
    page.on('pageerror', (e) =>
      console.log('PAGE ERROR', e?.message || String(e))
    )
    page.on('framenavigated', (fr) => console.log('NAVIGATED', fr.url()))

    // Use query param bootstrap to avoid any localStorage init
    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=smoke`,
      { waitUntil: 'domcontentloaded' }
    )

    // Expect the heading is visible
    const heading = page.getByRole('heading', { name: 'Admin Settings' })
    await expect(heading).toBeVisible({ timeout: 10000 })

    // Wait briefly to see if the page closes unexpectedly
    await page.waitForTimeout(1000)

    // Page should still be open
    expect(page.isClosed()).toBeFalsy()
  })
})
