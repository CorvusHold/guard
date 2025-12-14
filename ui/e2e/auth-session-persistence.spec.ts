import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

async function configureRuntime(
  page: import('@playwright/test').Page,
  mode: 'cookie' | 'bearer'
) {
  await page.goto(
    `${UI_BASE}/?guard-base-url=${encodeURIComponent(UI_BASE)}&auth-mode=${mode}&source=test`,
    { waitUntil: 'domcontentloaded' }
  )
  await expect(page.getByTestId('configured-base-url')).toHaveText(UI_BASE)
  await expect(page.getByTestId('configured-auth-mode')).toHaveText(mode)
}

async function registerLoginFlowRoutes(
  page: import('@playwright/test').Page,
  mode: 'cookie' | 'bearer'
) {
  const counters = {
    login: 0,
    meTotal: 0,
    meAuthed: 0
  }
  let sessionActive = false

  await page.route('**/api/v1/auth/login-options*', async (route) => {
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
    return route.fulfill({
      status: 200,
      headers: cors({ 'content-type': 'application/json' }),
      body: JSON.stringify({
        tenant_id: 'tenant_1',
        tenant_name: 'Acme Corp',
        user_exists: true,
        password_enabled: true,
        domain_matched_sso: false,
        sso_providers: []
      })
    })
  })

  await page.route('**/api/v1/auth/email/discover', async (route) => {
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
    return route.fulfill({
      status: 200,
      headers: cors({ 'content-type': 'application/json' }),
      body: JSON.stringify({
        found: true,
        user_exists: true,
        has_tenant: true,
        tenant_id: 'tenant_1',
        tenant_name: 'Acme Corp'
      })
    })
  })

  await page.route('**/api/v1/auth/password/login', async (route) => {
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
    counters.login += 1
    sessionActive = true
    const headers: Record<string, string> = { 'content-type': 'application/json' }
    if (mode === 'cookie') {
      headers['set-cookie'] = 'guard_session=abc123; Path=/; HttpOnly'
    }
    return route.fulfill({
      status: 200,
      headers: cors(headers),
      body:
        mode === 'bearer'
          ? JSON.stringify({ access_token: 'access-token', refresh_token: 'refresh-token' })
          : JSON.stringify({ ok: true })
    })
  })

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
    counters.meTotal += 1
    if (sessionActive) {
      counters.meAuthed += 1
      return route.fulfill({
        status: 200,
        headers: cors({ 'content-type': 'application/json' }),
        body: JSON.stringify({
          email: 'user@example.com',
          first_name: 'Session',
          last_name: 'Persisted'
        })
      })
    }
    return route.fulfill({
      status: 401,
      headers: cors({ 'content-type': 'application/json' }),
      body: JSON.stringify({ message: 'unauthorized' })
    })
  })

  return counters
}

async function completeLoginFlow(page: import('@playwright/test').Page) {
  await page.getByTestId('email-input').fill('user@example.com')
  await page.getByTestId('continue-button').click()
  await expect(page.getByTestId('password-input')).toBeVisible()
  await page.getByTestId('password-input').fill('super-secret')
  await Promise.all([
    page.waitForResponse((res) =>
      res.url().includes('/api/v1/auth/password/login') && res.request().method() === 'POST'
    ),
    page.getByTestId('signin-button').click()
  ])
  await expect(page.getByTestId('toast')).toContainText(/login successful/i)
}

async function gotoAdminAndWaitForMe(page: import('@playwright/test').Page) {
  await Promise.all([
    page.waitForResponse(
      (res) =>
        res.url().includes('/api/v1/auth/me') &&
        res.request().method() === 'GET' &&
        res.status() === 200
    ),
    page.goto(`${UI_BASE}/admin`, { waitUntil: 'domcontentloaded' })
  ])
  await expect(page.getByRole('heading', { name: 'Admin Settings' })).toBeVisible()
}

async function reloadAndAssertAdmin(page: import('@playwright/test').Page) {
  await Promise.all([
    page.waitForResponse(
      (res) =>
        res.url().includes('/api/v1/auth/me') &&
        res.request().method() === 'GET' &&
        res.status() === 200
    ),
    page.reload({ waitUntil: 'domcontentloaded' })
  ])
  await expect(page.getByRole('heading', { name: 'Admin Settings' })).toBeVisible()
}

test.describe('Auth session persistence', () => {
  test('cookie mode retains session after reload', async ({ page }) => {
    const counters = await registerLoginFlowRoutes(page, 'cookie')

    await configureRuntime(page, 'cookie')
    await completeLoginFlow(page)
    await gotoAdminAndWaitForMe(page)
    await reloadAndAssertAdmin(page)

    expect(counters.login).toBe(1)
    expect(counters.meAuthed).toBeGreaterThanOrEqual(2)
    expect(counters.meTotal).toBeGreaterThanOrEqual(3)
  })

  test('bearer mode retains session after reload', async ({ page }) => {
    const counters = await registerLoginFlowRoutes(page, 'bearer')

    await configureRuntime(page, 'bearer')
    await completeLoginFlow(page)

    await expect(
      page.evaluate(() => window.localStorage.getItem('guard_ui:guard_access_token'))
    ).resolves.toBe('access-token')

    await gotoAdminAndWaitForMe(page)
    await reloadAndAssertAdmin(page)

    expect(counters.login).toBe(1)
    expect(counters.meAuthed).toBeGreaterThanOrEqual(2)
    expect(counters.meTotal).toBeGreaterThanOrEqual(3)
  })
})
