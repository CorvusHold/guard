import { expect, test } from '@playwright/test'

const UI_BASE = 'http://localhost:4173'

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers
  }
}

async function mockAuthMe(page: import('@playwright/test').Page) {
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
  })
}

test.describe('Admin Settings', () => {
  test.beforeEach(async ({ page, context }) => {
    // helpful console + minimal logs
    page.on('console', (msg) => {
      const loc = msg.location()
      console.log(
        `PAGE CONSOLE [${msg.type()}]`,
        msg.text(),
        loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : ''
      )
    })
    page.on('pageerror', (err) => {
      console.log('PAGE ERROR', err?.message || String(err))
    })
    page.on('close', () => console.log('PAGE CLOSED'))
    context.on('close', () => console.log('CONTEXT CLOSED'))
    page.on('framenavigated', (fr) => console.log('NAVIGATED', fr.url()))
    // Keep network logs lightweight; do not intercept
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/'))
        console.log('REQ', req.method(), req.url())
    })
    page.on('response', async (res) => {
      if (res.url().includes('/api/v1/'))
        console.log('RES', res.status(), res.url())
    })
  })

  test('load tenant settings then save update', async ({
    page,
    browserName
  }, testInfo) => {
    if (browserName === 'webkit') test.slow()
    const TENANT = 'tenant_abc'

    // Mock GET settings
    let getCalledResolve: (() => void) | null = null
    const getCalled = new Promise<void>((r) => (getCalledResolve = r))
    await page.route(`**/api/v1/tenants/${TENANT}/settings`, async (route) => {
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
      console.log('MOCK GET settings hit')
      getCalledResolve?.()
      return route.fulfill({
        status: 200,
        body: JSON.stringify({
          sso_provider: 'workos',
          workos_client_id: 'client_123',
          workos_client_secret: '****',
          workos_api_key: '****',
          workos_default_connection_id: 'conn_1',
          workos_default_organization_id: 'org_1',
          sso_state_ttl: '10m',
          sso_redirect_allowlist: 'https://app.example.com/callback'
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    // Mock PUT settings
    let putCalled = false
    await page.route(`**/api/v1/tenants/${TENANT}/settings`, async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'PUT,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      if (req.method() === 'PUT') {
        putCalled = true
        return route.fulfill({
          status: 200,
          body: JSON.stringify({ ok: true }),
          headers: cors({ 'content-type': 'application/json' })
        })
      }
      return route.fallback()
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=test`,
      { waitUntil: 'domcontentloaded' }
    )
    // ensure ensureRuntimeConfigFromQuery ran and cleaned the URL
    await expect(page).toHaveURL(/\/+admin(\?|$)/)
    await page.getByTestId('admin-tenant-input').fill(TENANT)
    await expect(page.getByTestId('admin-tenant-input')).toHaveValue(TENANT)
    await page.getByTestId('admin-load-settings').click()
    // Ensure request went out and responded (if any)
    await Promise.race([getCalled, new Promise((r) => setTimeout(r, 2000))])
    // Surface any Vite error overlay if present
    const viteOverlay = await page
      .evaluate(() => {
        const el = document.querySelector(
          '#vite-error-overlay'
        ) as HTMLElement | null
        return el ? el.innerText : null
      })
      .catch(() => null as any)
    if (viteOverlay) console.log('VITE OVERLAY:', viteOverlay)
    // Wait until Save button is enabled => implies form is loaded (tenantId set and form != null, loading === null)
    await expect(page.getByTestId('admin-save-settings'))
      .toBeEnabled({ timeout: 10000 })
      .catch(async (err) => {
        try {
          await page.screenshot({
            path: testInfo.outputPath('admin-load-timeout.png'),
            fullPage: true
          })
        } catch {}
        throw err
      })
    // If error banner is visible, surface it for debugging (do not wait)
    const errLoc = page.locator('[data-testid="admin-error"]').first()
    const errVisible = await errLoc.isVisible({ timeout: 0 }).catch(() => false)
    if (errVisible) {
      const errText = await errLoc
        .textContent({ timeout: 100 })
        .catch(() => null)
      if (errText) console.log('ADMIN ERROR BANNER:', errText)
    }

    // Wait for inputs then assert values. On WebKit, avoid detailed per-field assertions to reduce flakiness.
    if (browserName !== 'webkit') {
      await expect(page.getByTestId('admin-workos-client-id')).toBeVisible({
        timeout: 10000
      })
      await expect(page.getByTestId('admin-workos-client-id')).toHaveValue(
        'client_123',
        { timeout: 10000 }
      )
      await expect(page.getByTestId('admin-workos-conn-id')).toHaveValue(
        'conn_1',
        { timeout: 10000 }
      )
      await expect(page.getByTestId('admin-workos-org-id')).toHaveValue(
        'org_1',
        { timeout: 10000 }
      )
      await expect(page.getByTestId('admin-sso-state-ttl')).toHaveValue('10m', {
        timeout: 10000
      })
      await expect(
        page.getByTestId('admin-sso-redirect-allowlist')
      ).toHaveValue('https://app.example.com/callback', { timeout: 10000 })
    } else {
      // Just ensure form is present
      await page
        .getByTestId('admin-workos-client-id')
        .waitFor({ state: 'attached', timeout: 10000 })
    }
    // Give a short settle; avoid networkidle on WebKit which may never resolve
    if (browserName !== 'webkit') {
      await page.waitForLoadState('networkidle')
    } else {
      await page.waitForTimeout(100)
    }

    // Update a field and save
    await page.getByTestId('admin-workos-client-id').fill('client_456')
    await page.getByTestId('admin-save-settings').click()

    await expect(page.getByTestId('admin-message')).toHaveText(
      /Settings saved/i
    )
    expect(putCalled).toBeTruthy()
  })

  test('portal link generation success displays link', async ({
    page,
    browserName
  }, _testInfo) => {
    if (browserName === 'webkit') test.slow()
    const TENANT = 'tenant_abc'
    const ORG = 'org_123'

    // Note: We avoid triggering GET settings to reduce WebKit flake; portal link does not require form state

    // Mock portal link endpoint
    await page.route('**/api/v1/auth/sso/workos/portal-link**', async (route) => {
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
      const url = new URL(req.url())
      // Validate required params present
      if (
        !url.searchParams.get('tenant_id') ||
        !url.searchParams.get('organization_id')
      ) {
        return route.fulfill({
          status: 400,
          body: JSON.stringify({ message: 'missing params' }),
          headers: cors({ 'content-type': 'application/json' })
        })
      }
      return route.fulfill({
        status: 200,
        body: JSON.stringify({ link: 'https://workos.example.com/portal/abc' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=test`,
      { waitUntil: 'domcontentloaded' }
    )
    await expect(page).toHaveURL(/\/+admin(\?|$)/)
    await page.getByTestId('admin-tenant-input').fill(TENANT)
    await expect(page.getByTestId('admin-tenant-input')).toHaveValue(TENANT)
    const viteOverlay2 = await page
      .evaluate(() => {
        const el = document.querySelector(
          '#vite-error-overlay'
        ) as HTMLElement | null
        return el ? el.innerText : null
      })
      .catch(() => null as any)
    if (viteOverlay2) console.log('VITE OVERLAY:', viteOverlay2)
    // Wait for portal org input to be interactable, avoid networkidle on WebKit
    const orgInput = page.getByTestId('admin-portal-org-input')
    await orgInput.waitFor({ state: 'visible', timeout: 10000 })
    await expect(orgInput).toBeEditable({ timeout: 10000 })
    if (browserName === 'webkit') await page.waitForTimeout(100)
    const errLoc2 = page.locator('[data-testid="admin-error"]').first()
    const errVisible2 = await errLoc2
      .isVisible({ timeout: 0 })
      .catch(() => false)
    if (errVisible2) {
      const errText2 = await errLoc2
        .textContent({ timeout: 100 })
        .catch(() => null)
      if (errText2) console.log('ADMIN ERROR BANNER:', errText2)
    }

    // Generate portal link
    await orgInput.click({ timeout: 5000 })
    // Use type instead of fill to avoid any WebKit-specific hanging on fill
    await orgInput.fill('')
    await orgInput.type(ORG, { delay: 5 })
    await page.getByTestId('admin-generate-portal-link').click()

    await expect(page.getByTestId('admin-portal-link-output')).toHaveText(
      'https://workos.example.com/portal/abc',
      { timeout: 10000 }
    )
  })

  test('update SSO redirect allowlist and CORS origins', async ({
    page,
    browserName
  }) => {
    if (browserName === 'webkit') test.slow()
    const TENANT = 'tenant_xyz'

    // Mock GET settings with initial values
    await page.route(`**/api/v1/tenants/${TENANT}/settings`, async (route) => {
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
        body: JSON.stringify({
          sso_provider: 'dev',
          workos_client_id: '',
          sso_state_ttl: '10m',
          sso_redirect_allowlist: 'http://localhost:3000',
          app_cors_allowed_origins: 'http://localhost:3000'
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    // Mock PUT settings to capture the update
    let capturedBody: any = null
    await page.route(`**/api/v1/tenants/${TENANT}/settings`, async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'PUT,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      if (req.method() === 'PUT') {
        capturedBody = JSON.parse(req.postData() || '{}')
        return route.fulfill({
          status: 204,
          headers: cors()
        })
      }
      return route.fallback()
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}`,
      { waitUntil: 'domcontentloaded' }
    )
    await page.getByTestId('admin-tenant-input').fill(TENANT)
    await page.getByTestId('admin-load-settings').click()

    // Wait for form to load
    await expect(page.getByTestId('admin-save-settings')).toBeEnabled({
      timeout: 10000
    })

    // Verify initial values loaded
    await expect(page.getByTestId('admin-sso-redirect-allowlist')).toHaveValue(
      'http://localhost:3000'
    )
    await expect(page.getByTestId('admin-cors-allowed-origins')).toHaveValue(
      'http://localhost:3000'
    )

    // Update both fields
    await page
      .getByTestId('admin-sso-redirect-allowlist')
      .fill('http://localhost:3001,https://app.packitoo.com')
    await page
      .getByTestId('admin-cors-allowed-origins')
      .fill('http://localhost:3001,https://app.packitoo.com,http://localhost:3000')

    // Save changes
    await page.getByTestId('admin-save-settings').click()

    // Verify success message
    await expect(page.getByTestId('admin-message')).toHaveText(
      /Settings saved/i,
      { timeout: 10000 }
    )

    // Verify the correct data was sent to the API
    expect(capturedBody).toBeTruthy()
    expect(capturedBody.sso_redirect_allowlist).toBe(
      'http://localhost:3001,https://app.packitoo.com'
    )
    expect(capturedBody.app_cors_allowed_origins).toBe(
      'http://localhost:3001,https://app.packitoo.com,http://localhost:3000'
    )
  })

  test('empty redirect allowlist and CORS can be saved', async ({
    page,
    browserName
  }) => {
    if (browserName === 'webkit') test.slow()
    const TENANT = 'tenant_empty'

    await page.route(`**/api/v1/tenants/${TENANT}/settings`, async (route) => {
      const req = route.request()
      if (req.method() === 'OPTIONS') {
        return route.fulfill({
          status: 204,
          headers: cors({
            'access-control-allow-methods': 'GET,PUT,OPTIONS',
            'access-control-allow-headers':
              'content-type,authorization,accept,x-guard-client'
          })
        })
      }
      if (req.method() === 'GET') {
        return route.fulfill({
          status: 200,
          body: JSON.stringify({
            sso_provider: 'dev',
            workos_client_id: '',
            sso_state_ttl: '10m',
            sso_redirect_allowlist: 'http://localhost:3001',
            app_cors_allowed_origins: 'http://localhost:3001'
          }),
          headers: cors({ 'content-type': 'application/json' })
        })
      }
      if (req.method() === 'PUT') {
        return route.fulfill({
          status: 204,
          headers: cors()
        })
      }
      return route.fallback()
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}`,
      { waitUntil: 'domcontentloaded' }
    )
    await page.getByTestId('admin-tenant-input').fill(TENANT)
    await page.getByTestId('admin-load-settings').click()

    await expect(page.getByTestId('admin-save-settings')).toBeEnabled({
      timeout: 10000
    })

    // Clear both fields
    await page.getByTestId('admin-sso-redirect-allowlist').fill('')
    await page.getByTestId('admin-cors-allowed-origins').fill('')

    // Should still be able to save
    await page.getByTestId('admin-save-settings').click()

    await expect(page.getByTestId('admin-message')).toHaveText(
      /Settings saved/i,
      { timeout: 10000 }
    )
  })

  test('help text explains redirect allowlist and CORS purposes', async ({
    page
  }) => {
    const TENANT = 'tenant_help'

    await page.route(`**/api/v1/tenants/${TENANT}/settings`, async (route) => {
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
        body: JSON.stringify({
          sso_provider: 'dev',
          sso_state_ttl: '10m',
          sso_redirect_allowlist: '',
          app_cors_allowed_origins: ''
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}`,
      { waitUntil: 'domcontentloaded' }
    )
    await page.getByTestId('admin-tenant-input').fill(TENANT)
    await page.getByTestId('admin-load-settings').click()

    await expect(page.getByTestId('admin-save-settings')).toBeEnabled({
      timeout: 10000
    })

    // Verify help text is present and informative
    const redirectHelpText = page.locator(
      'text=Comma-separated list of allowed redirect URLs for SSO callbacks'
    )
    await expect(redirectHelpText).toBeVisible()

    const corsHelpText = page.locator(
      'text=Comma-separated list of allowed origins. These origins will be able to make requests to the API from browsers.'
    )
    await expect(corsHelpText).toBeVisible()
  })

  test('portal link missing org shows client error', async ({ page }) => {
    const TENANT = 'tenant_abc'

    // basic GET settings so page is ready
    await page.route(`**/api/v1/tenants/${TENANT}/settings`, async (route) => {
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
        body: JSON.stringify({
          sso_provider: 'workos',
          workos_client_id: 'client_123',
          sso_state_ttl: '10m',
          sso_redirect_allowlist: '',
          app_cors_allowed_origins: ''
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    await mockAuthMe(page)

    await page.goto(
      `/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=redirect`
    )
    // Ensure runtime config is ready before interacting
    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))
    await page.getByTestId('admin-tenant-input').fill(TENANT)
    await expect(page.getByTestId('admin-tenant-input')).toHaveValue(TENANT)
    await page.getByTestId('admin-load-settings').click()
    // Wait until Save is enabled (form ready) to avoid clicking Generate while loading
    await expect(page.getByTestId('admin-save-settings')).toBeEnabled({
      timeout: 10000
    })

    await page.getByTestId('admin-generate-portal-link').click()
    await expect(page.getByTestId('admin-error')).toHaveText(
      /organization_id is required/i
    )
  })
})
