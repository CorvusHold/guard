import { expect, test } from '@playwright/test'

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

async function mockAuthMe(page: import('@playwright/test').Page) {
  await page.route('**/v1/auth/me', async (route) => {
    if (await allowOptions(route, 'GET,OPTIONS')) return
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

test.describe('Admin Users & Sessions', () => {
  test.beforeEach(async ({ page, context }) => {
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
    context.on('close', () => console.log('CONTEXT CLOSED'))
    page.on('request', (req) => {
      if (req.url().includes('/v1/'))
        console.log('REQ', req.method(), req.url())
    })
    page.on('response', async (res) => {
      if (res.url().includes('/v1/'))
        console.log('RES', res.status(), res.url())
    })
  })

  test('users and sessions errors show banners and toasts', async ({
    page
  }) => {
    const TENANT = 'tenant_users'

    // Users list -> 500
    await page.route('**/v1/auth/admin/users?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return
      return route.fulfill({
        status: 500,
        body: JSON.stringify({ message: 'server error' }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })
    // Sessions list -> 500
    await page.route('**/v1/auth/sessions', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return
      return route.fulfill({ status: 500, headers: cors({}) })
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=users`,
      { waitUntil: 'domcontentloaded' }
    )

    // Wait for users tab to be visible and active
    await page.waitForSelector('[data-testid="tab-users"]', { timeout: 10000 })
    await page.getByTestId('admin-tenant-input').fill(TENANT)

    // Wait for users-refresh button to be enabled and clickable
    await expect(page.getByTestId('users-refresh')).toBeEnabled({ timeout: 10000 })

    // Trigger users refresh -> expect error banner and toast text
    await page.getByTestId('users-refresh').click({ force: true })
    await expect(page.getByTestId('users-error')).toBeVisible()
    await expect(page.getByText(/Failed to load users/i)).toBeVisible()

    // Navigate to My Account tab and verify sessions error path shows toast/banner
    await page.getByTestId('tab-account').click()
    await expect(page.getByText(/My Sessions/i)).toBeVisible()
    await expect(page.getByText(/Failed to load sessions/i)).toBeVisible()
  })

  test('users list, edit names, block/unblock; my sessions list/revoke', async ({
    page
  }) => {
    const TENANT = 'tenant_users'

    // Initial users list
    await page.route('**/v1/auth/admin/users?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return
      return route.fulfill({
        status: 200,
        body: JSON.stringify({
          users: [
            {
              id: 'u_1',
              email_verified: true,
              is_active: true,
              first_name: 'A',
              last_name: 'One',
              roles: ['admin'],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
              last_login_at: null
            }
          ]
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })

    // Edit names PATCH
    await page.route('**/v1/auth/admin/users/u_1', async (route) => {
      if (await allowOptions(route, 'PATCH,OPTIONS')) return
      if (route.request().method() === 'PATCH') {
        // After editing names, subsequent list reflects update
        page.route('**/v1/auth/admin/users?tenant_id=*', async (route2) => {
          if (await allowOptions(route2, 'GET,OPTIONS')) return
          return route2.fulfill({
            status: 200,
            body: JSON.stringify({
              users: [
                {
                  id: 'u_1',
                  email_verified: true,
                  is_active: true,
                  first_name: 'A2',
                  last_name: 'One2',
                  roles: ['admin'],
                  created_at: new Date().toISOString(),
                  updated_at: new Date().toISOString(),
                  last_login_at: null
                }
              ]
            }),
            headers: cors({ 'content-type': 'application/json' })
          })
        })
        return route.fulfill({ status: 204, headers: cors({}) })
      }
      return route.fallback()
    })

    // Block/unblock
    await page.route('**/v1/auth/admin/users/u_1/block', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      // After block, list shows inactive
      page.route('**/v1/auth/admin/users?tenant_id=*', async (route2) => {
        if (await allowOptions(route2, 'GET,OPTIONS')) return
        return route2.fulfill({
          status: 200,
          body: JSON.stringify({
            users: [
              {
                id: 'u_1',
                email_verified: true,
                is_active: false,
                first_name: 'A2',
                last_name: 'One2',
                roles: ['admin'],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                last_login_at: null
              }
            ]
          }),
          headers: cors({ 'content-type': 'application/json' })
        })
      })
      return route.fulfill({ status: 204, headers: cors({}) })
    })
    await page.route('**/v1/auth/admin/users/u_1/unblock', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      // After unblock, list shows active again
      page.route('**/v1/auth/admin/users?tenant_id=*', async (route2) => {
        if (await allowOptions(route2, 'GET,OPTIONS')) return
        return route2.fulfill({
          status: 200,
          body: JSON.stringify({
            users: [
              {
                id: 'u_1',
                email_verified: true,
                is_active: true,
                first_name: 'A2',
                last_name: 'One2',
                roles: ['admin'],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                last_login_at: null
              }
            ]
          }),
          headers: cors({ 'content-type': 'application/json' })
        })
      })
      return route.fulfill({ status: 204, headers: cors({}) })
    })

    // Sessions list and revoke
    await page.route('**/v1/auth/sessions', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return
      return route.fulfill({
        status: 200,
        body: JSON.stringify({
          sessions: [
            {
              id: 's_1',
              revoked: false,
              user_agent: 'UA',
              ip: '127.0.0.1',
              created_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 86400000).toISOString()
            }
          ]
        }),
        headers: cors({ 'content-type': 'application/json' })
      })
    })
    await page.route('**/v1/auth/sessions/s_1/revoke', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      // After revoke, list returns []
      page.route('**/v1/auth/sessions', async (route2) => {
        if (await allowOptions(route2, 'GET,OPTIONS')) return
        return route2.fulfill({
          status: 200,
          body: JSON.stringify({ sessions: [] }),
          headers: cors({ 'content-type': 'application/json' })
        })
      })
      return route.fulfill({ status: 204, headers: cors({}) })
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=users`,
      { waitUntil: 'domcontentloaded' }
    )
    await expect(page).toHaveURL(/\/+admin(\?|$)/)

    // Wait for users tab to be visible and active
    await page.waitForSelector('[data-testid="tab-users"]', { timeout: 10000 })

    // Enter tenant and load
    await page.getByTestId('admin-tenant-input').fill(TENANT)
    await page.getByTestId('admin-load-settings').click()

    // Wait for users-refresh button to be enabled and clickable
    await expect(page.getByTestId('users-refresh')).toBeEnabled({ timeout: 10000 })

    // Users panel should show one user
    await page.getByTestId('users-refresh').click({ force: true })
    await expect(page.getByTestId('users-item-u_1')).toBeVisible({
      timeout: 10000
    })

    // Edit names via modal
    await page.getByTestId('users-edit-u_1').click()
    await page.getByLabel('First name').fill('A2')
    await page.getByLabel('Last name').fill('One2')
    await page.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByTestId('users-item-u_1')).toContainText('A2 One2', {
      timeout: 10000
    })

    // Block
    await page.getByTestId('users-toggle-u_1').click()
    await expect(page.getByTestId('users-item-u_1')).toContainText('blocked', {
      timeout: 10000
    })

    // Unblock
    await page.getByTestId('users-toggle-u_1').click()
    await expect(page.getByTestId('users-item-u_1')).toContainText('active', {
      timeout: 10000
    })

    // Sessions section should show session then disappear after revoke
    await expect(page.getByText('My Sessions')).toBeVisible()
    await expect(page.getByText('UA')).toBeVisible({ timeout: 10000 })
    await page.getByRole('button', { name: 'Revoke' }).click()
    await expect(page.getByText('No active sessions.')).toBeVisible({
      timeout: 10000
    })
  })
})
