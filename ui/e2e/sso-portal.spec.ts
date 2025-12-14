import { expect, test } from '@playwright/test'

const API_BASE = 'http://localhost:8081'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

test.describe('SSO Setup Portal', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/**', async (route) => {
      const req = route.request()
      console.log('ROUTE CATCHALL', req.method(), req.url())
      await route.fallback()
    })
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/')) console.log('REQ', req.method(), req.url())
    })
    page.on('response', async (res) => {
      if (res.url().includes('/api/v1/')) console.log('RES', res.status(), res.url())
    })
    page.on('console', (msg) => {
      const loc = msg.location()
      console.log(
        `PAGE CONSOLE [${msg.type()}]`,
        msg.text(),
        loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : ''
      )
    })
  })

  test('shows portal context and provider details on success', async ({ page }) => {
    let sessionResolve: (() => void) | null = null
    const sessionHit = new Promise<void>((r) => (sessionResolve = r))
    await page.route('**/api/v1/sso/portal/session', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'POST,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const fulfilled = await route.fulfill({
        status: 200,
        body: JSON.stringify({
          tenant_id: 't-1',
          provider_slug: 'oidc-main',
          portal_token_id: 'pt-1'
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
      sessionResolve?.()
      return fulfilled
    })

    let providerResolve: (() => void) | null = null
    const providerHit = new Promise<void>((r) => (providerResolve = r))
    await page.route('**/api/v1/sso/portal/provider', async (route) => {
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
          id: 'prov-1',
          tenant_id: 't-1',
          name: 'OIDC Main',
          slug: 'oidc-main',
          provider_type: 'oidc',
          enabled: true,
          allow_signup: true,
          trust_email_verified: true,
          issuer: 'https://accounts.example.com',
          domains: ['example.com']
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
      providerResolve?.()
      return fulfilled
    })

    await page.goto(
      `/portal/sso-setup?guard-base-url=${encodeURIComponent(
        API_BASE
      )}&source=redirect&token=raw-token-123`
    )

    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))
    await sessionHit
    await providerHit

    const success = page.getByTestId('sso-setup-success')
    await expect(success).toBeVisible()
    await expect(page.getByText('SSO Setup Portal')).toBeVisible()
    await expect(success).toContainText(/Tenant ID:\s*t-1/)
    await expect(success).toContainText(/Portal Token ID:\s*pt-1/)
    await expect(success).toContainText(/Name:\s*OIDC Main/)
    await expect(success).toContainText(/Slug:\s*oidc-main/)
    await expect(success).toContainText(/Type:\s*oidc/)
    await expect(success).toContainText(
      /Issuer:\s*https:\/\/accounts\.example\.com/
    )

    await expect(page.getByTestId('sso-setup-loading')).not.toBeVisible()

    await expect(page).not.toHaveURL(/token=/)
    await expect(page).not.toHaveURL(/guard-base-url=/)
  })

  test('shows error UI when portal session fails', async ({ page }) => {
    let sessionResolve: (() => void) | null = null
    const sessionHit = new Promise<void>((r) => (sessionResolve = r))
    await page.route('**/api/v1/sso/portal/session', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'POST,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const fulfilled = await route.fulfill({
        status: 400,
        body: JSON.stringify({ error: 'invalid portal token' }),
        headers: cors({ 'content-type': 'application/json' })
      })
      sessionResolve?.()
      return fulfilled
    })

    await page.goto(
      `/portal/sso-setup?guard-base-url=${encodeURIComponent(
        API_BASE
      )}&source=redirect&token=bad-token`
    )

    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))
    await sessionHit

    await expect(page.getByTestId('sso-setup-error')).toBeVisible()
    await expect(page.getByTestId('sso-setup-error')).toContainText(
      /portal session failed/i
    )
  })
})
