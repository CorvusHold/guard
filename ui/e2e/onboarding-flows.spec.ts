import { test, expect } from '@playwright/test'

const API = 'http://localhost:8081'

function api(url: string): string { return `${API}${url}` }

test.describe('Onboarding flows', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    // Configure Guard base URL if needed
    const baseUrlInput = page.locator('[data-testid="base-url-input"]')
    if (await baseUrlInput.isVisible()) {
      await baseUrlInput.fill(API)
      // leave auth mode as default (bearer)
      await page.click('[data-testid="save-config"]')
      await expect(page.locator('[data-testid="login-form"]')).toBeVisible()
    }
  })

  test('Discovery -> no tenant -> TenantCreate -> Admin', async ({ page }) => {
    const email = `owner_${Date.now()}@example.com`
    const tenantID = `00000000-0000-4000-8000-${Date.now()}`

    // 1) Mock discovery (no tenant)
    await page.route(api('/v1/auth/email/discover'), async (route) => {
      const body = await route.request().postDataJSON()
      expect(body.email).toBe(email)
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ found: false, has_tenant: false, user_exists: false, suggestions: [] })
      })
    })

    // 2) Enter email and continue
    await page.fill('[data-testid="email-input"]', email)
    await page.click('[data-testid="continue-button"]')

    // 3) Click Create New Organization -> navigates to /tenant/create with prefilled params
    await page.click('[data-testid="create-tenant-button"]')
    await expect(page).toHaveURL(/\/tenant\/create/)

    // 4) Mock tenant create + signup + login + settings
    await page.route(api('/tenants'), async (route) => {
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({ id: tenantID, name: 'acme', is_active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() })
      })
    })
    await page.route(api('/v1/auth/password/signup'), async (route) => {
      const b = await route.request().postDataJSON()
      expect(b.tenant_id).toBe(tenantID)
      await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ access_token: 'at', refresh_token: 'rt' }) })
    })
    await page.route(api('/v1/auth/password/login'), async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ access_token: 'at2', refresh_token: 'rt2' }) })
    })
    await page.route(api(`/v1/tenants/${tenantID}/settings`), async (route) => {
      if (route.request().method() === 'PUT') {
        const body = await route.request().postDataJSON()
        expect(body.sso_provider).toBe('dev')
        expect(typeof body.sso_redirect_allowlist).toBe('string')
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) })
      } else {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ settings: {} }) })
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

    // 1) Mock discovery (has tenant but user not found)
    await page.route(api('/v1/auth/email/discover'), async (route) => {
      const body = await route.request().postDataJSON()
      expect(body.email).toBe(email)
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ found: false, has_tenant: true, tenant_id: tenantID, tenant_name: 'Acme', user_exists: false })
      })
    })

    // 2) Enter email and continue
    await page.fill('[data-testid="email-input"]', email)
    await page.click('[data-testid="continue-button"]')

    // 3) Click Create Account -> navigates to /signup
    await page.click('[data-testid="create-account-button"]')
    await expect(page).toHaveURL(new RegExp(`/signup`))

    // 4) Mock password signup
    await page.route(api('/v1/auth/password/signup'), async (route) => {
      const b = await route.request().postDataJSON()
      expect(b.tenant_id).toBe(tenantID)
      expect(b.email).toBe(email)
      await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ access_token: 'at', refresh_token: 'rt' }) })
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
