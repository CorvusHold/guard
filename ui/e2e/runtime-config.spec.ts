import { expect, test } from '@playwright/test'

const API_URL = 'http://localhost:8081'

// Helper to clear localStorage before each test navigation. Must be same-origin.
async function clearStorage(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.evaluate(() => localStorage.clear())
}

test.describe('Runtime config bootstrap', () => {
  test('shows form when no config; saving persists and shows configured state', async ({
    page
  }) => {
    await clearStorage(page)

    await expect(page.getByTestId('base-url-input')).toBeVisible()
    await page.getByTestId('base-url-input').fill(API_URL)
    await page.getByTestId('save-config').click()

    await expect(page.getByTestId('configured-base-url')).toHaveText(API_URL)

    const stored = await page.evaluate(() =>
      localStorage.getItem('guard_runtime')
    )
    expect(stored).not.toBeNull()
    const parsed = JSON.parse(stored!)
    expect(parsed.guard_base_url).toBe(API_URL)
    expect(parsed.source).toBe('direct')
  })

  test('query params guard-base-url and source=redirect auto-persist and clean URL', async ({
    page
  }) => {
    await clearStorage(page)
    await page.goto(
      `/?guard-base-url=${encodeURIComponent(API_URL)}&source=redirect`
    )

    await expect(page.getByTestId('configured-base-url')).toHaveText(API_URL)

    // URL should be cleaned (no guard-base-url param)
    expect(page.url()).not.toContain('guard-base-url=')

    const stored = await page.evaluate(() =>
      localStorage.getItem('guard_runtime')
    )
    const parsed = JSON.parse(stored!)
    expect(parsed.source).toBe('redirect')
  })

  test('uses existing localStorage config across reloads', async ({ page }) => {
    await clearStorage(page)
    // seed storage
    await page.evaluate(
      (apiUrl) =>
        localStorage.setItem(
          'guard_runtime',
          JSON.stringify({ guard_base_url: apiUrl, source: 'direct' })
        ),
      API_URL
    )

    await page.reload()
    await expect(page.getByTestId('configured-base-url')).toHaveText(API_URL)
  })

  test('reset config clears storage and shows form again', async ({ page }) => {
    await clearStorage(page)

    await page.getByTestId('base-url-input').fill(API_URL)
    await page.getByTestId('save-config').click()
    await expect(page.getByTestId('configured-base-url')).toHaveText(API_URL)

    await page.getByTestId('reset-config').click()
    await expect(page.getByTestId('base-url-input')).toBeVisible()
    const stored = await page.evaluate(() =>
      localStorage.getItem('guard_runtime')
    )
    expect(stored).toBeNull()
  })
})
