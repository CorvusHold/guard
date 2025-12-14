import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'
const API_URL = UI_BASE

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
    `${UI_BASE}/?guard-base-url=${encodeURIComponent(API_URL)}&source=redirect`
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
  await page.route('**/api/v1/auth/password/login', async (route) => {
    const req = route.request()
    console.log('ROUTE HIT /api/v1/auth/password/login', req.method(), req.url())
    if (req.method() === 'OPTIONS') {
      console.log('ROUTE FULFILL /api/v1/auth/password/login OPTIONS 204')
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
      console.log('ROUTE FULFILL /api/v1/auth/password/login 400 tenant required')
      return route.fulfill({
        status: 400,
        body: JSON.stringify({ message: 'tenant required' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    }
    console.log('ROUTE FULFILL /api/v1/auth/password/login 200')
    return route.fulfill({
      status: 200,
      body: JSON.stringify({ access_token: 'acc', refresh_token: 'ref' }),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
}

async function routeLoginOptions(
  page: import('@playwright/test').Page,
  body: Record<string, unknown>
): Promise<void> {
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
      body: JSON.stringify(body),
      headers: cors({ 'content-type': 'application/json' })
    })
  })
}

test.describe('Login flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      try {
        localStorage.removeItem('guard_ui:guard_access_token')
        localStorage.removeItem('guard_ui:guard_refresh_token')
      } catch {}
    })

    await page.route('**/api/v1/auth/refresh', async (route) => {
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
        status: 401,
        body: JSON.stringify({ message: 'unauthorized' }),
        headers: cors({ 'content-type': 'application/json' })
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

      const auth = req.headers()['authorization'] || ''
      if (auth.toLowerCase().startsWith('bearer ')) {
        return route.fulfill({
          status: 200,
          body: JSON.stringify({
            email: 'user@example.com',
            first_name: 'Ada',
            last_name: 'Lovelace'
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
  test('password login success', async ({ page }) => {
    await setupRuntime(page)

    await routeLoginOptions(page, {
      tenant_id: 'tenant_1',
      tenant_name: 'Acme',
      user_exists: true,
      password_enabled: true,
      domain_matched_sso: null,
      sso_required: false,
      sso_providers: []
    })

    await routePasswordLoginSuccess(page)

    const emailInput = page.getByTestId('email-input')
    await emailInput.fill('user@example.com')
    await page.getByTestId('continue-button').click()

    const pwdInput = page.getByTestId('password-input')
    await expect(pwdInput).toBeVisible()
    await pwdInput.fill('secret')
    await page.getByTestId('signin-button').click()

    await expect(page.getByTestId('user-email')).toHaveText('user@example.com')
  })

  test('tenant required then success after providing tenant', async ({
    page
  }) => {
    await setupRuntime(page)

    await routeLoginOptions(page, {
      tenant_id: '',
      tenant_name: '',
      user_exists: true,
      password_enabled: true,
      domain_matched_sso: null,
      sso_required: false,
      sso_providers: []
    })

    await routePasswordLoginSuccess(page)

    const emailInput2 = page.getByTestId('email-input')
    await emailInput2.fill('user@example.com')
    await page.getByTestId('continue-button').click()

    const pwdInput2 = page.getByTestId('password-input')
    await expect(pwdInput2).toBeVisible()
    await pwdInput2.fill('secret')
    await page.getByTestId('signin-button').click()
    await expect(page.getByTestId('login-error')).toBeVisible()

    // Retry with tenant_id provided via URL (tenant context)
    await page.goto(
      `${UI_BASE}/?guard-base-url=${encodeURIComponent(API_URL)}&source=redirect&tenant_id=tenant_1`,
      { waitUntil: 'domcontentloaded' }
    )

    await routeLoginOptions(page, {
      tenant_id: 'tenant_1',
      tenant_name: 'Acme',
      user_exists: true,
      password_enabled: true,
      domain_matched_sso: null,
      sso_required: false,
      sso_providers: []
    })

    await page.getByTestId('email-input').fill('user@example.com')
    await page.getByTestId('continue-button').click()
    await page.getByTestId('password-input').fill('secret')
    await page.getByTestId('signin-button').click()

    await expect(page.getByTestId('user-email')).toHaveText('user@example.com')
  })

  test('MFA challenge (202) shows banner', async ({ page }) => {
    await setupRuntime(page)

    await routeLoginOptions(page, {
      tenant_id: 'tenant_1',
      tenant_name: 'Acme',
      user_exists: true,
      password_enabled: true,
      domain_matched_sso: null,
      sso_required: false,
      sso_providers: []
    })

    // Route login to return 202 MFA
    let loginResolve: (() => void) | null = null
    const loginHit = new Promise<void>((r) => (loginResolve = r))
    await page.route('**/api/v1/auth/password/login', async (route) => {
      const req = route.request()
      console.log(
        'ROUTE HIT /api/v1/auth/password/login (MFA 202)',
        req.method(),
        req.url()
      )
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /api/v1/auth/password/login OPTIONS 204')
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'POST,GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      console.log('ROUTE FULFILL /api/v1/auth/password/login 202')
      const fulfilled = await route.fulfill({
        status: 202,
        body: JSON.stringify({ challenge_token: 'mfa-123' }),
        headers: cors({ 'content-type': 'application/json' })
      })
      loginResolve?.()
      return fulfilled
    })

    const emailInput3 = page.getByTestId('email-input')
    await emailInput3.fill('user@example.com')
    await page.getByTestId('continue-button').click()
    const pwdInput3 = page.getByTestId('password-input')
    await expect(pwdInput3).toBeVisible()
    await pwdInput3.fill('secret')
    await Promise.all([loginHit, page.getByTestId('signin-button').click()])
    await expect(page.getByTestId('mfa-code-input')).toBeVisible()
  })

  test('MFA verify flow completes login', async ({ page }) => {
    await setupRuntime(page)

    await routeLoginOptions(page, {
      tenant_id: 'tenant_1',
      tenant_name: 'Acme',
      user_exists: true,
      password_enabled: true,
      domain_matched_sso: null,
      sso_required: false,
      sso_providers: []
    })

    // Route login to return 202 MFA
    let loginResolve2: (() => void) | null = null
    const _loginHit2 = new Promise<void>((r) => (loginResolve2 = r))
    await page.route('**/api/v1/auth/password/login', async (route) => {
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
    await page.route('**/api/v1/auth/mfa/verify', async (route) => {
      const req = route.request()
      console.log('ROUTE HIT /api/v1/auth/mfa/verify', req.method(), req.url())
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /api/v1/auth/mfa/verify OPTIONS 204')
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
        console.log('ROUTE FULFILL /api/v1/auth/mfa/verify 200')
        const fulfilled = await route.fulfill({
          status: 200,
          body: JSON.stringify({ access_token: 'acc', refresh_token: 'ref' }),
          headers: cors({ 'content-type': 'application/json' })
        })
        mfaResolve?.()
        return fulfilled
      }
      console.log('ROUTE FULFILL /api/v1/auth/mfa/verify 400')
      return route.fulfill({
        status: 400,
        body: JSON.stringify({ message: 'invalid code' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await page.getByTestId('email-input').fill('user@example.com')
    await page.getByTestId('continue-button').click()
    await page.getByTestId('password-input').fill('secret')
    await page.getByTestId('signin-button').click()
    await expect(page.getByTestId('mfa-code-input')).toBeVisible()
    await page.getByTestId('mfa-code-input').fill('123456')
    await Promise.all([mfaHit, page.getByTestId('mfa-verify-button').click()])

    await expect(page.getByTestId('user-email')).toHaveText('user@example.com')
  })

  test('Tenant discovery -> select tenant -> login success', async ({ page }) => {
    await setupRuntime(page)

    // Login flow now uses /api/v1/auth/login-options rather than a tenant discovery form.
    await routeLoginOptions(page, {
      tenant_id: 'tenant_2',
      tenant_name: 'Beta',
      user_exists: true,
      password_enabled: true,
      domain_matched_sso: null,
      sso_required: false,
      sso_providers: []
    })

    await routePasswordLoginSuccess(page)

    await page.getByTestId('email-input').fill('user@example.com')
    await page.getByTestId('continue-button').click()
    await page.getByTestId('password-input').fill('secret')
    await page.getByTestId('signin-button').click()
    await expect(page.getByTestId('user-email')).toHaveText('user@example.com')
  })

  test('SSO start (dev) navigates to redirect_url', async ({ page }) => {
    await setupRuntime(page)

    await routeLoginOptions(page, {
      tenant_id: 'tenant_1',
      tenant_name: 'Acme',
      user_exists: true,
      password_enabled: false,
      domain_matched_sso: null,
      sso_required: false,
      sso_providers: [
        {
          slug: 'dev',
          name: 'Dev',
          login_url: `${API_URL}/api/v1/auth/sso/dev/start`
        }
      ]
    })

    // Intercept SSO start to return 302 with Location header (SDK reads Location)
    let ssoResolve: (() => void) | null = null
    const ssoHit = new Promise<void>((r) => (ssoResolve = r))
    await page.route('**/api/v1/auth/sso/dev/start*', async (route) => {
      const req = route.request()
      console.log('ROUTE HIT /api/v1/auth/sso/dev/start', req.method(), req.url())
      if (req.method() === 'OPTIONS') {
        console.log('ROUTE FULFILL /api/v1/auth/sso/dev/start OPTIONS 204')
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      console.log('ROUTE FULFILL /api/v1/auth/sso/dev/start 200 (HTML redirect)')
      const fulfilled = await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body:
          '<!doctype html><html><head><meta charset="utf-8" />' +
          '<meta http-equiv="refresh" content="0; url=https://example.com/sso-dev" />' +
          '</head><body><script>window.location.replace("https://example.com/sso-dev")</script></body></html>'
      })
      ssoResolve?.()
      return fulfilled
    })

    await page.getByTestId('email-input').fill('user@example.com')
    await page.getByTestId('continue-button').click()

    await Promise.all([ssoHit, page.getByTestId('sso-button-dev').click()])
    await page.waitForURL('https://example.com/sso-dev', { timeout: 15000 })
    await expect(page).toHaveURL('https://example.com/sso-dev')
  })
})
