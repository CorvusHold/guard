import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

test.describe('OAuth2 Discovery in UI', () => {
  test.beforeEach(async ({ page }) => {
    page.on('console', (msg) => {
      const loc = msg.location()
      console.log(
        `PAGE CONSOLE [${msg.type()}]`,
        msg.text(),
        loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : ''
      )
    })
    page.on('pageerror', (err) =>
      console.log('PAGE ERROR', err?.message || String(err))
    )
  })

  test('discovers server auth mode and auto-applies', async ({ page }) => {
    // Mock discovery endpoint
    await page.route('**/.well-known/oauth-authorization-server', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers': 'content-type'
          })
        })
      }
      return route.fulfill({
        status: 200,
        body: JSON.stringify({
          issuer: 'http://localhost:8081',
          token_endpoint: 'http://localhost:8081/v1/auth/refresh',
          guard_auth_modes_supported: ['bearer', 'cookie'],
          guard_auth_mode_default: 'cookie',
          guard_version: '1.0.0'
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await page.goto(`${UI_BASE}/`, { waitUntil: 'domcontentloaded' })

    // Should see config screen
    await expect(page.getByRole('heading', { name: 'Configure Guard' })).toBeVisible()

    // Enter base URL
    await page.getByTestId('base-url-input').fill('http://localhost:8081')

    // Discovery button should appear
    await expect(page.getByTestId('discover-button')).toBeVisible()

    // Click discovery
    await page.getByTestId('discover-button').click()

    // Should show discovered mode
    await expect(page.getByTestId('discovered-mode')).toBeVisible()
    await expect(page.getByTestId('discovered-mode')).toContainText('cookie')

    // Auth mode select should be updated to cookie
    const select = page.getByTestId('auth-mode-select')
    await expect(select).toHaveValue('cookie')
  })

  test('shows error when discovery fails', async ({ page }) => {
    // Mock discovery endpoint with error
    await page.route('**/.well-known/oauth-authorization-server', async (route) => {
      return route.fulfill({
        status: 404,
        body: JSON.stringify({ error: 'not found' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await page.goto(`${UI_BASE}/`, { waitUntil: 'domcontentloaded' })

    // Enter base URL
    await page.getByTestId('base-url-input').fill('http://localhost:8081')

    // Click discovery
    await page.getByTestId('discover-button').click()

    // Should show error message
    await expect(page.getByTestId('discovery-error')).toBeVisible()
    await expect(page.getByTestId('discovery-error')).toContainText('Failed')
  })

  test('resets discovery state when URL changes', async ({ page }) => {
    // Mock successful discovery
    await page.route('**/.well-known/oauth-authorization-server', async (route) => {
      return route.fulfill({
        status: 200,
        body: JSON.stringify({
          guard_auth_mode_default: 'bearer',
          guard_auth_modes_supported: ['bearer', 'cookie']
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await page.goto(`${UI_BASE}/`, { waitUntil: 'domcontentloaded' })

    // Enter base URL and discover
    await page.getByTestId('base-url-input').fill('http://localhost:8081')
    await page.getByTestId('discover-button').click()

    // Should show discovered mode
    await expect(page.getByTestId('discovered-mode')).toBeVisible()

    // Change URL
    await page.getByTestId('base-url-input').fill('http://localhost:8082')

    // Discovered mode should disappear
    await expect(page.getByTestId('discovered-mode')).not.toBeVisible()
  })

  test('discovery button only appears when URL is entered', async ({ page }) => {
    await page.goto(`${UI_BASE}/`, { waitUntil: 'domcontentloaded' })

    // Initially no discovery button
    await expect(page.getByTestId('discover-button')).not.toBeVisible()

    // Enter URL
    await page.getByTestId('base-url-input').fill('http://localhost:8081')

    // Now button should appear
    await expect(page.getByTestId('discover-button')).toBeVisible()
  })
})
