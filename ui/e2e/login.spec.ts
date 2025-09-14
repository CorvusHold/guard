import { expect, test } from '@playwright/test'

const API_URL = 'http://localhost:5173'

function rxEscape(s: string): string {
  return s.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')
}

function _absApi(path: string): RegExp {
  const p = path.startsWith('/') ? path : `/${path}`
  return new RegExp(`^https?://[^/]+${rxEscape(p)}(\\?.*)?$`)
}

function _matchPath(u: unknown, path: string): boolean {
  try {
    if (typeof u === 'string') {
      return new URL(u).pathname === path
    }
    const maybe = u as { pathname?: string }
    if (maybe && typeof maybe.pathname === 'string')
      return maybe.pathname === path
  } catch {
    if (typeof u === 'string') return u.includes(path)
  }
  return false
}

async function setupRuntime(page: import('@playwright/test').Page) {
  await page.goto(
    `/?guard-base-url=${encodeURIComponent(API_URL)}&source=redirect`
  )
  await expect(page.getByTestId('configured-base-url')).toHaveText(API_URL)
}

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

async function routePasswordLoginSuccess(
  page: import('@playwright/test').Page
): Promise<void> {
  await page.route('**/v1/auth/password/login', async (route) => {
    const req = route.request()
    console.log('ROUTE HIT /v1/auth/password/login', req.method(), req.url())
    if (req.method() === 'OPTIONS') {
      console.log('ROUTE FULFILL /v1/auth/password/login OPTIONS 204')
      return route.fulfill({
        status: 204,
        headers: cors({
          'access-control-allow-methods': 'POST,GET,OPTIONS',
          'access-control-allow-headers':
            'content-type,authorization,accept,x-guard-client'
        })
      })
    }
    const body = req.postDataJSON?.() as any
    // If tenant required and not provided, return 400
    if (body?.email && body.password && !body.tenant_id) {
      console.log('ROUTE FULFILL /v1/auth/password/login 400 tenant required')
      return route.fulfill({
        status: 400,
        body: JSON.stringify({ message: 'tenant required' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    }
    console.log('ROUTE FULFILL /v1/auth/password/login 200')
    return route.fulfill({
      status: 200,
      body: JSON.stringify({ access_token: 'acc', refresh_token: 'ref' }),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
  await page.route('**/v1/auth/me', async (route) => {
    const req = route.request()
    console.log('ROUTE HIT /v1/auth/me', req.method(), req.url())
    if (req.method() === 'OPTIONS') {
      console.log('ROUTE FULFILL /v1/auth/me OPTIONS 204')
      return route.fulfill({
        status: 204,
        headers: cors({
          'access-control-allow-methods': 'GET,OPTIONS',
          'access-control-allow-headers':
            'content-type,authorization,accept,x-guard-client'
        })
      })
    }
    console.log('ROUTE FULFILL /v1/auth/me 200')
    return route.fulfill({
      status: 200,
      body: JSON.stringify({
        email: 'user@example.com',
        first_name: 'Ada',
        last_name: 'Lovelace'
      }),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
}

test.describe('Login flow', () => {
  test.beforeEach(async ({ page }) => {
    // Log fetch calls from within the page
    await page.addInitScript(() => {
      try {
        const orig = window.fetch.bind(window)
        ;(window as any).__origFetch = orig
        window.fetch = (async (...args: any[]) => {
          try {
            const input = args[0]
            const url =
              typeof input === 'string' ? input : input?.url || String(input)
            // eslint-disable-next-line no-console
            console.log('PAGE FETCH', url)
          } catch {}
          return (window as any).__origFetch(...args)
        }) as any
      } catch {}
    })
    // Catch-all logger for any /v1/** requests to verify routing and matching
    await page.route('**/v1/**', async (route) => {
      const req = route.request()
      console.log('ROUTE CATCHALL', req.method(), req.url())
      await route.fallback()
    })
    // Global debug logging for API traffic
    page.on('request', (req) => {
      if (req.url().includes('/v1/'))
        console.log('REQ', req.method(), req.url())
    })
    page.on('response', async (res) => {
      if (res.url().includes('/v1/'))
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
  test('password login success', async ({ page }) => {
    await setupRuntime(page)

    // Force success on first try by including tenant
    await routePasswordLoginSuccess(page)

    const emailInput = page.getByTestId('login-email')
    const pwdInput = page.getByTestId('login-password')
    const tenantInput = page.getByTestId('login-tenant')
    await emailInput.fill('user@example.com')
    await pwdInput.fill('secret')
    await tenantInput.fill('tenant_1')
    await expect(tenantInput).toHaveValue('tenant_1')
    await page.getByTestId('login-submit').click()
    await expect(page.locator('text=Logged in')).toBeVisible()
    await expect(page.locator('text=Email: user@example.com')).toBeVisible()
  })

  test('tenant required then success after providing tenant', async ({
    page
  }) => {
    await setupRuntime(page)

    await routePasswordLoginSuccess(page)

    const emailInput2 = page.getByTestId('login-email')
    const pwdInput2 = page.getByTestId('login-password')
    await emailInput2.fill('user@example.com')
    await pwdInput2.fill('secret')
    await page.getByTestId('login-submit').click()
    await expect(page.getByTestId('login-error')).toBeVisible()
    await expect(page.getByText('required for this account')).toBeVisible()

    const tenantInput2 = page.getByTestId('login-tenant')
    await tenantInput2.fill('tenant_1')
    await expect(tenantInput2).toHaveValue('tenant_1')
    await page.getByTestId('login-submit').click()
    await expect(page.locator('text=Logged in')).toBeVisible()
  })

  test('MFA challenge (202) shows banner', async ({ page }) => {
    await setupRuntime(page)

    // Route login to return 202 MFA
    let loginResolve: (() => void) | null = null
    const loginHit = new Promise<void>((r) => (loginResolve = r))
    await page.route('**/v1/auth/password/login', async (route) => {
      const req = route.request()
      console.log(
        'ROUTE HIT /v1/auth/password/login (MFA 202)',
        req.method(),
        req.url()
      )
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /v1/auth/password/login OPTIONS 204')
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'POST,GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      console.log('ROUTE FULFILL /v1/auth/password/login 202')
      const fulfilled = await route.fulfill({
        status: 202,
        body: JSON.stringify({ challenge_token: 'mfa-123' }),
        headers: cors({ 'content-type': 'application/json' })
      })
      loginResolve?.()
      return fulfilled
    })

    const emailInput3 = page.getByTestId('login-email')
    const pwdInput3 = page.getByTestId('login-password')
    await emailInput3.fill('user@example.com')
    await pwdInput3.fill('secret')
    await Promise.all([loginHit, page.getByTestId('login-submit').click()])
    await expect(page.getByTestId('login-mfa')).toBeVisible()
  })

  test('MFA verify flow completes login', async ({ page }) => {
    await setupRuntime(page)

    // Route login to return 202 MFA
    let loginResolve2: (() => void) | null = null
    const _loginHit2 = new Promise<void>((r) => (loginResolve2 = r))
    await page.route('**/v1/auth/password/login', async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'POST,GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const fulfilled = await route.fulfill({
        status: 202,
        body: JSON.stringify({ challenge_token: 'mfa-123' }),
        headers: cors({ 'content-type': 'application/json' })
      })
      loginResolve2?.()
      return fulfilled
    })

    // Route MFA verify -> 200 tokens when code correct
    let mfaResolve: (() => void) | null = null
    const mfaHit = new Promise<void>((r) => (mfaResolve = r))
    await page.route('**/v1/auth/mfa/verify', async (route) => {
      const req = route.request()
      console.log('ROUTE HIT /v1/auth/mfa/verify', req.method(), req.url())
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /v1/auth/mfa/verify OPTIONS 204')
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'POST,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const body = req.postDataJSON?.() as any
      if (body?.challenge_token === 'mfa-123' && body?.code === '123456') {
        console.log('ROUTE FULFILL /v1/auth/mfa/verify 200')
        const fulfilled = await route.fulfill({
          status: 200,
          body: JSON.stringify({ access_token: 'acc', refresh_token: 'ref' }),
          headers: cors({ 'content-type': 'application/json' })
        })
        mfaResolve?.()
        return fulfilled
      }
      console.log('ROUTE FULFILL /v1/auth/mfa/verify 400')
      return route.fulfill({
        status: 400,
        body: JSON.stringify({ message: 'invalid code' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    // Route me -> profile
    let meResolve: (() => void) | null = null
    const meHit = new Promise<void>((r) => (meResolve = r))
    await page.route('**/v1/auth/me', async (route) => {
      const req = route.request()
      console.log('ROUTE HIT /v1/auth/me (MFA flow)', req.method(), req.url())
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /v1/auth/me OPTIONS 204')
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      console.log('ROUTE FULFILL /v1/auth/me 200')
      const fulfilled = await route.fulfill({
        status: 200,
        body: JSON.stringify({
          email: 'user@example.com',
          first_name: 'Grace',
          last_name: 'Hopper'
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
      meResolve?.()
      return fulfilled
    })

    await page.getByTestId('login-email').fill('user@example.com')
    await page.getByTestId('login-password').fill('secret')
    await page.getByTestId('login-submit').click()
    await expect(page.getByTestId('login-mfa')).toBeVisible()
    await page.getByTestId('mfa-code').fill('123456')
    await Promise.all([mfaHit, page.getByTestId('mfa-verify').click()])
    await meHit
    await expect(page.locator('text=Logged in')).toBeVisible({ timeout: 15000 })
    await expect(page.locator('text=Email: user@example.com')).toBeVisible()
  })

  test('Tenant discovery -> select tenant -> login success', async ({
    page
  }) => {
    await setupRuntime(page)

    // discovery endpoint
    let tenantsResolve: (() => void) | null = null
    const tenantsHit = new Promise<void>((r) => (tenantsResolve = r))
    await page.route('**/v1/auth/tenants*', async (route) => {
      const req = route.request()
      console.log('ROUTE HIT /v1/auth/tenants', req.method(), req.url())
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /v1/auth/tenants OPTIONS 204')
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      const url = new URL(req.url())
      const email = url.searchParams.get('email')
      console.log('ROUTE FULFILL /v1/auth/tenants 200 email=', email)
      const fulfilled = await route.fulfill({
        status: 200,
        body: JSON.stringify({
          tenants: email
            ? [
                { id: 'tenant_1', name: 'Acme' },
                { id: 'tenant_2', name: 'Beta' }
              ]
            : []
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
      tenantsResolve?.()
      return fulfilled
    })

    await routePasswordLoginSuccess(page)

    const emailInput5 = page.getByTestId('login-email')
    await emailInput5.fill('user@example.com')
    await Promise.all([tenantsHit, page.getByTestId('login-discover').click()])
    await expect(page.getByTestId('tenant-select')).toBeVisible()
    await page.getByTestId('tenant-select').selectOption('tenant_2')
    await expect(page.getByTestId('login-tenant')).toHaveValue('tenant_2')

    const pwdInput5 = page.getByTestId('login-password')
    await pwdInput5.fill('secret')
    await page.getByTestId('login-submit').click()
    await expect(page.locator('text=Logged in')).toBeVisible()
  })

  test('SSO start (dev) navigates to redirect_url', async ({ page }) => {
    await setupRuntime(page)

    // Intercept SSO start to return 302 with Location header (SDK reads Location)
    let ssoResolve: (() => void) | null = null
    const ssoHit = new Promise<void>((r) => (ssoResolve = r))
    await page.route('**/v1/auth/sso/dev/start*', async (route) => {
      const req = route.request()
      console.log('ROUTE HIT /v1/auth/sso/dev/start', req.method(), req.url())
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /v1/auth/sso/dev/start OPTIONS 204')
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      console.log('ROUTE FULFILL /v1/auth/sso/dev/start 200 (Location header)')
      const fulfilled = await route.fulfill({
        status: 200,
        headers: cors({ location: 'https://example.com/sso-dev' })
      })
      ssoResolve?.()
      return fulfilled
    })

    await Promise.all([ssoHit, page.getByTestId('login-sso-dev').click()])
    await page.waitForURL('https://example.com/sso-dev', { timeout: 15000 })
    await expect(page).toHaveURL('https://example.com/sso-dev')
  })
})
