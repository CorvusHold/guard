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
        'access-control-allow-headers': 'content-type,authorization,accept,x-guard-client'
      })
    })
  }
}

async function mockAuthMe(page: import('@playwright/test').Page) {
  await page.route('**/api/v1/auth/me', async (route) => {
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

test.describe('Admin Tenants: create and list', () => {
  test.beforeEach(async ({ page, context }) => {
    // Set runtime to cookie auth and target base URL
    await page.addInitScript((apiBase: string) => {
      localStorage.setItem(
        'guard_runtime',
        JSON.stringify({ guard_base_url: apiBase, auth_mode: 'cookie', source: 'e2e' })
      )
    }, UI_BASE)

    // Light logging for debugging
    page.on('console', (msg) => {
      const loc = msg.location()
      console.log(
        `PAGE CONSOLE [${msg.type()}]`,
        msg.text(),
        loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : ''
      )
    })
    page.on('pageerror', (err) => console.log('PAGE ERROR', err?.message || String(err)))
    context.on('close', () => console.log('CONTEXT CLOSED'))
  })

  test('create tenant and see it in list', async ({ page, browserName }) => {
    if (browserName === 'webkit') test.slow()

    const EXISTING = { id: 'ten_existing', name: 'ExistingCo', is_active: true }
    const NEW = { id: 'ten_new', name: 'NewCo', is_active: true }

    let created = false
    let signupCalled = false

    // List tenants
    await page.route('**/api/v1/tenants**', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS,POST')) return
      const req = route.request()
      if (req.method() === 'GET') {
        return route.fulfill({
          status: 200,
          body: JSON.stringify({
            items: created ? [EXISTING, NEW] : [EXISTING],
            total: created ? 2 : 1,
            page: 1,
            page_size: 10,
            total_pages: 1
          }),
          headers: cors({ 'content-type': 'application/json' })
        })
      }
      if (req.method() === 'POST') {
        created = true
        return route.fulfill({
          status: 201,
          body: JSON.stringify({
            id: NEW.id,
            name: NEW.name,
            is_active: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }),
          headers: cors({ 'content-type': 'application/json' })
        })
      }
      return route.fallback()
    })

    // Password signup for admin user in new tenant
    await page.route('**/api/v1/auth/password/signup', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return
      signupCalled = true
      return route.fulfill({ status: 201, body: JSON.stringify({ ok: true }), headers: cors({ 'content-type': 'application/json' }) })
    })

    await mockAuthMe(page)

    await page.goto(
      `${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&auth_mode=cookie&source=tenants`,
      { waitUntil: 'domcontentloaded' }
    )
    // Switch to Tenants tab
    await page.getByTestId('tab-tenants').click()

    // Existing tenant appears
    await expect(page.getByText(EXISTING.name)).toBeVisible({ timeout: 10000 })

    // Go to Create tab inside Tenant Management
    await page.getByRole('tab', { name: 'Create Tenant' }).click()

    // Fill form
    await page.getByTestId('tenant-name').fill(NEW.name)
    await page.getByTestId('admin-first-name').fill('Alice')
    await page.getByTestId('admin-last-name').fill('Admin')
    await page.getByTestId('admin-email').fill('alice.admin@example.com')
    await page.getByTestId('admin-password').fill('SuperSecret1!')

    await page.getByTestId('create-tenant').click()

    // Success banner
    await expect(page.getByTestId('creation-success')).toBeVisible({ timeout: 10000 })
    await expect(page.getByTestId('created-tenant-name')).toHaveText(NEW.name)

    // After creation, tab auto-switches back to list and should show new tenant
    await expect(page.getByTestId('tab-tenants')).toBeVisible({ timeout: 10000 })
    await page.getByRole('tab', { name: 'Tenant List' }).click()
    await expect(page.getByText(NEW.name)).toBeVisible({ timeout: 10000 })

    expect(created).toBeTruthy()
    expect(signupCalled).toBeTruthy()
  })
})
