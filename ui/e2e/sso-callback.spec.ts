import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'
const TENANT_ID = 'tenant-123'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

test.describe('SSO Callback', () => {
  test.beforeEach(async ({ page }) => {
    // Catch-all logger for any /api/v1/** requests to verify routing and matching
    await page.route('**/api/v1/**', async (route) => {
      const req = route.request()
      console.log('ROUTE CATCHALL', req.method(), req.url())
      await route.fallback()
    })
    // Global debug logging for API traffic
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/'))
        console.log('REQ', req.method(), req.url())
    })
    page.on('response', async (res) => {
      if (res.url().includes('/api/v1/'))
        console.log('RES', res.status(), res.url())
    })
    // Surface page console logs (including errors)
    page.on('console', (msg) => {
      const loc = msg.location()
      console.log(
        `PAGE CONSOLE [${msg.type()}]`,
        msg.text(),
        loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : ''
      )
    })
  })
  test('workos callback success persists tokens and shows profile', async ({
    page
  }) => {
    // Synchronize on callback and profile
    let cbResolve: (() => void) | null = null
    const cbHit = new Promise<void>((r) => (cbResolve = r))
    await page.route('**/auth/sso/t/*/workos/callback*', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const fulfilled = await route.fulfill({
        status: 200,
        body: JSON.stringify({ access_token: 'acc', refresh_token: 'ref' }),
        headers: cors({ 'content-type': 'application/json' })
      })
      cbResolve?.()
      return fulfilled
    })

    let meResolve: (() => void) | null = null
    const meHit = new Promise<void>((r) => (meResolve = r))
    await page.route('**/api/v1/auth/me', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const fulfilled = await route.fulfill({
        status: 200,
        body: JSON.stringify({
          email: 'user@example.com',
          first_name: 'Ada',
          last_name: 'Lovelace'
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
      meResolve?.()
      return fulfilled
    })

    await page.goto(
      `/auth/callback?guard-base-url=${encodeURIComponent(UI_BASE)}&source=redirect&provider=workos&code=abc123&state=xyz&tenant_id=${encodeURIComponent(TENANT_ID)}&email=${encodeURIComponent('user@example.com')}`
    )
    // Ensure runtime config is persisted before SDK calls
    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))
    await cbHit // ensure callback processed
    await meHit // ensure profile fetched

    await expect(page.getByText('Sign-in completed')).toBeVisible()
    await expect(page.getByText('Signed in as user@example.com')).toBeVisible()
  })

  test('workos callback error shows error UI', async ({ page }) => {
    let cbResolve: (() => void) | null = null
    const cbHit = new Promise<void>((r) => (cbResolve = r))
    await page.route('**/auth/sso/t/*/workos/callback*', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const fulfilled = await route.fulfill({
        status: 401,
        body: JSON.stringify({ message: 'invalid state' }),
        headers: cors({ 'content-type': 'application/json' })
      })
      cbResolve?.()
      return fulfilled
    })

    await page.goto(
      `/auth/callback?guard-base-url=${encodeURIComponent(UI_BASE)}&source=redirect&provider=workos&code=bad&tenant_id=${encodeURIComponent(TENANT_ID)}`
    )
    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))
    await cbHit // ensure callback processed

    await expect(page.getByTestId('callback-error')).toBeVisible()
    // Transport throws ApiError and UI surfaces message from body.message
    await expect(page.getByTestId('callback-error')).toContainText(
      /invalid state/i,
      { timeout: 10000 }
    )
  })

  test('unsupported provider yields error', async ({ page }) => {
    await page.goto(
      `/auth/callback?guard-base-url=${encodeURIComponent(UI_BASE)}&source=redirect&provider=foo&code=xyz`
    )
    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))
    await expect(page.getByTestId('callback-error')).toBeVisible()
    await expect(page.getByText('Unsupported provider: foo')).toBeVisible()
  })

  test('missing code yields error', async ({ page }) => {
    await page.goto(
      `/auth/callback?guard-base-url=${encodeURIComponent(UI_BASE)}&source=redirect&provider=workos`
    )
    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))
    await expect(page.getByTestId('callback-error')).toBeVisible()
    await expect(page.getByText('Missing provider or code')).toBeVisible()
  })
})
