import { test, expect } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

async function allowOptions(route: any, allow: string) {
  const req = route.request()
  if (req.method() === 'OPTIONS') {
    return route.fulfill({
      status: 204,
      headers: cors({
        'access-control-allow-methods': allow,
        'access-control-allow-headers':
          'content-type,authorization,accept,x-guard-client'
      })
    })
  }
}

test.describe('Onboarding flows', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(UI_BASE)
    // Configure Guard base URL if needed
    const baseUrlInput = page.locator('[data-testid="base-url-input"]')
    if (await baseUrlInput.isVisible()) {
      await baseUrlInput.fill(UI_BASE)
      // leave auth mode as default (bearer)
      await page.click('[data-testid="save-config"]')
      await expect(page.getByTestId('email-input')).toBeVisible()
    }

    // Stable auth mocks for post-signup redirect into /admin
    await page.route('**/api/v1/auth/refresh', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      return route.fulfill({
        status: 401,
        body: JSON.stringify({ message: 'unauthorized' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })
    await page.route('**/api/v1/auth/me', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return

      const auth = route.request().headers()['authorization'] || ''
      if (auth.toLowerCase().startsWith('bearer ')) {
        return route.fulfill({
          status: 200,
          body: JSON.stringify({
            email: 'admin@example.com',
            first_name: 'Admin',
            last_name: 'User',
            roles: ['admin']
          }),
          headers: cors({ 'content-type': 'application/json' })
        })
      }

      return route.fulfill({
        status: 401,
        body: JSON.stringify({ message: 'unauthorized' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })
  })

  test('Discovery -> no tenant -> TenantCreate -> Admin', async ({ page }) => {
    const email = `owner_${Date.now()}@example.com`
    const tenantID = `00000000-0000-4000-8000-${Date.now()}`

    // Navigate directly to the onboarding page
    await page.goto(`${UI_BASE}/tenant/create?email=${encodeURIComponent(email)}&name=acme`, {
      waitUntil: 'domcontentloaded'
    })

    // Mock tenant create + signup + login + settings
    await page.route('**/api/v1/tenants', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      await route.fulfill({
        status: 201,
        headers: cors({ 'content-type': 'application/json' }),
        body: JSON.stringify({ id: tenantID, name: 'acme', is_active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() })
      })
    })
    await page.route('**/api/v1/auth/password/signup', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      const b = await route.request().postDataJSON()
      expect(b.tenant_id).toBe(tenantID)
      await route.fulfill({
        status: 201,
        headers: cors({ 'content-type': 'application/json' }),
        body: JSON.stringify({ access_token: 'at', refresh_token: 'rt' })
      })
    })
    await page.route('**/api/v1/auth/password/login', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      await route.fulfill({
        status: 200,
        headers: cors({ 'content-type': 'application/json' }),
        body: JSON.stringify({ access_token: 'at2', refresh_token: 'rt2' })
      })
    })
    await page.route(`**/api/v1/tenants/${tenantID}/settings`, async (route) => {
      if (await allowOptions(route, 'GET,PUT,OPTIONS')) return
      if (route.request().method() === 'PUT') {
        const body = await route.request().postDataJSON()
        expect(body.sso_provider).toBe('dev')
        expect(typeof body.sso_redirect_allowlist).toBe('string')
        await route.fulfill({
          status: 200,
          headers: cors({ 'content-type': 'application/json' }),
          body: JSON.stringify({ ok: true })
        })
      } else {
        await route.fulfill({
          status: 200,
          headers: cors({ 'content-type': 'application/json' }),
          body: JSON.stringify({ settings: {} })
        })
      }
    })

    // 5) Fill tenant create form and submit
    await page.fill('[data-testid="tenant-create-org"]', 'acme')
    await page.fill('[data-testid="tenant-create-first"]', 'Alice')
    await page.fill('[data-testid="tenant-create-last"]', 'Owner')
    await page.fill('[data-testid="tenant-create-email"]', email)
    await page.fill('[data-testid="tenant-create-password"]', 'Password123!')
    await page.click('[data-testid="tenant-create-submit"]')

    // 6) Redirect to /admin and show Admin Settings
    await expect(page).toHaveURL(/\/admin/)
    await expect(page.getByText('Admin Settings')).toBeVisible()
  })

  test('Discovery -> has tenant, user not found -> Signup -> Admin', async ({ page }) => {
    const email = `user_${Date.now()}@example.com`
    const tenantID = `11111111-1111-4111-8111-${Date.now()}`

    await page.goto(
      `${UI_BASE}/signup?tenant_id=${encodeURIComponent(tenantID)}&email=${encodeURIComponent(email)}`,
      { waitUntil: 'domcontentloaded' }
    )

    // Mock password signup
    await page.route('**/api/v1/auth/password/signup', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      const b = await route.request().postDataJSON()
      expect(b.tenant_id).toBe(tenantID)
      expect(b.email).toBe(email)
      await route.fulfill({
        status: 201,
        headers: cors({ 'content-type': 'application/json' }),
        body: JSON.stringify({ access_token: 'at', refresh_token: 'rt' })
      })
    })

    // 5) Fill signup form and submit
    await page.fill('[data-testid="signup-tenant"]', tenantID)
    await page.fill('[data-testid="signup-first"]', 'Bob')
    await page.fill('[data-testid="signup-last"]', 'User')
    await page.fill('[data-testid="signup-email"]', email)
    await page.fill('[data-testid="signup-password"]', 'Password123!')
    await page.click('[data-testid="signup-submit"]')

    // 6) Redirect to /admin and show Admin Settings
    await expect(page).toHaveURL(/\/admin/)
    await expect(page.getByText('Admin Settings')).toBeVisible()
  })
})
