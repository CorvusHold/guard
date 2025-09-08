import { test, expect } from '@playwright/test';

const UI_BASE = 'http://localhost:4173';

function cors(headers: Record<string, string> = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'location,x-request-id,content-type',
    ...headers,
  };
}

async function allowOptions(route: any, allow: string) {
  const req = route.request();
  if (req.method() === 'OPTIONS') {
    return route.fulfill({ status: 204, headers: cors({ 'access-control-allow-methods': allow, 'access-control-allow-headers': 'content-type,authorization,accept,x-guard-client' }) });
  }
}

test.describe('Admin RBAC', () => {
  test.beforeEach(async ({ page, context }) => {
    page.on('console', (msg) => {
      const loc = msg.location();
      console.log(`PAGE CONSOLE [${msg.type()}]`, msg.text(), loc?.url ? `@ ${loc.url}:${loc.lineNumber}:${loc.columnNumber}` : '');
    });
    page.on('pageerror', (err) => console.log('PAGE ERROR', err?.message || String(err)));
    context.on('close', () => console.log('CONTEXT CLOSED'));
    page.on('request', (req) => { if (req.url().includes('/v1/')) console.log('REQ', req.method(), req.url()); });
    page.on('response', async (res) => { if (res.url().includes('/v1/')) console.log('RES', res.status(), res.url()); });
  });

  test('roles CRUD flow', async ({ page, browserName }, testInfo) => {
    const TENANT = 'tenant_rbac';

    // List roles (initial empty)
    await page.route('**/v1/auth/admin/rbac/roles?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 200, body: JSON.stringify({ roles: [] }), headers: cors({ 'content-type': 'application/json' }) });
    });

    // Create role
    let createdId = 'role_1';
    await page.route('**/v1/auth/admin/rbac/roles', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return;
      if (route.request().method() === 'POST') {
        const body = JSON.parse(route.request().postData() || '{}');
        if (!body?.tenant_id || !body?.name) {
          return route.fulfill({ status: 400, body: JSON.stringify({ message: 'bad request' }), headers: cors({ 'content-type': 'application/json' }) });
        }
        // After create, next list will include this role
        page.route('**/v1/auth/admin/rbac/roles?tenant_id=*', async (route2) => {
          if (await allowOptions(route2, 'GET,OPTIONS')) return;
          return route2.fulfill({ status: 200, body: JSON.stringify({ roles: [{ id: createdId, name: body.name, description: body.description, tenant_id: body.tenant_id }] }), headers: cors({ 'content-type': 'application/json' }) });
        });
        return route.fulfill({ status: 201, body: JSON.stringify({ id: createdId, name: body.name, description: body.description, tenant_id: body.tenant_id }), headers: cors({ 'content-type': 'application/json' }) });
      }
      return route.fallback();
    });

    // Update role
    await page.route('**/v1/auth/admin/rbac/roles/*', async (route) => {
      const req = route.request();
      if (await allowOptions(route, 'PATCH,DELETE,OPTIONS')) return;
      const url = new URL(req.url());
      if (req.method() === 'PATCH') {
        const body = JSON.parse(req.postData() || '{}');
        page.route('**/v1/auth/admin/rbac/roles?tenant_id=*', async (route2) => {
          if (await allowOptions(route2, 'GET,OPTIONS')) return;
          return route2.fulfill({ status: 200, body: JSON.stringify({ roles: [{ id: createdId, name: body.name || 'roleA', description: body.description || 'descA', tenant_id: body.tenant_id || TENANT }] }), headers: cors({ 'content-type': 'application/json' }) });
        });
        return route.fulfill({ status: 200, body: JSON.stringify({ id: createdId, name: body.name, description: body.description, tenant_id: body.tenant_id || TENANT }), headers: cors({ 'content-type': 'application/json' }) });
      }
      if (req.method() === 'DELETE') {
        // Return empty list after delete
        page.route('**/v1/auth/admin/rbac/roles?tenant_id=*', async (route2) => {
          if (await allowOptions(route2, 'GET,OPTIONS')) return;
          return route2.fulfill({ status: 200, body: JSON.stringify({ roles: [] }), headers: cors({ 'content-type': 'application/json' }) });
        });
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      return route.fallback();
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=rbac-roles`, { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/+admin$/);
    await page.getByTestId('admin-tenant-input').fill(TENANT);
    await page.getByTestId('rbac-roles-refresh').click();
    await expect(page.getByTestId('rbac-roles-empty')).toBeVisible();

    // Create role
    await page.getByTestId('rbac-role-new-name').fill('roleA');
    await page.getByTestId('rbac-role-new-desc').fill('descA');
    await page.getByTestId('rbac-role-create').click();

    await expect(page.getByTestId(`rbac-role-item-${createdId}`)).toBeVisible({ timeout: 10000 });

    // Update role name
    const nameInput = page.getByTestId(`rbac-role-item-${createdId}`).locator('input').nth(0);
    await nameInput.fill('roleB');
    await nameInput.blur();

    // Update role description
    const descInput = page.getByTestId(`rbac-role-item-${createdId}`).locator('input').nth(1);
    await descInput.fill('descB');
    await descInput.blur();

    // Delete role
    await page.getByTestId(`rbac-role-delete-${createdId}`).click();
    await expect(page.getByTestId('rbac-roles-empty')).toBeVisible({ timeout: 10000 });
  });

  test('role permissions grant and revoke', async ({ page }) => {
    const TENANT = 'tenant_rbac';

    // List roles for selection
    await page.route('**/v1/auth/admin/rbac/roles?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 200, body: JSON.stringify({ roles: [{ id: 'role_1', name: 'role1', tenant_id: TENANT }] }), headers: cors({ 'content-type': 'application/json' }) });
    });

    // Grant
    await page.route('**/v1/auth/admin/rbac/roles/role_1/permissions', async (route) => {
      if (await allowOptions(route, 'POST,DELETE,OPTIONS')) return;
      const req = route.request();
      if (req.method() === 'POST') {
        const body = JSON.parse(req.postData() || '{}');
        if (!body?.permission_key) return route.fulfill({ status: 400, body: JSON.stringify({ message: 'bad request' }), headers: cors({ 'content-type': 'application/json' }) });
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      if (req.method() === 'DELETE') {
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      return route.fallback();
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=rbac-perms`, { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/+admin$/);
    await page.getByTestId('admin-tenant-input').fill(TENANT);

    // Load roles for permissions panel
    await page.getByTestId('rbac-perms-load-roles').click();
    await page.getByTestId('rbac-perms-role-select').selectOption('role_1');
    await page.getByTestId('rbac-perms-key').fill('users.read');
    await page.getByTestId('rbac-perms-scope').fill('tenant');
    await page.getByTestId('rbac-perms-grant').click();
    await expect(page.getByTestId('rbac-perms-message')).toHaveText(/granted/i);

    await page.getByTestId('rbac-perms-revoke').click();
    await expect(page.getByTestId('rbac-perms-message')).toHaveText(/revoked/i);
  });

  test('user roles list, add and remove', async ({ page }) => {
    const TENANT = 'tenant_rbac';
    const USER = 'user_123';

    // List user roles (initial empty)
    await page.route(`**/v1/auth/admin/rbac/users/${USER}/roles?tenant_id=*`, async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 200, body: JSON.stringify({ role_ids: [] }), headers: cors({ 'content-type': 'application/json' }) });
    });

    // Add user role
    await page.route(`**/v1/auth/admin/rbac/users/${USER}/roles`, async (route) => {
      if (await allowOptions(route, 'POST,DELETE,OPTIONS')) return;
      const req = route.request();
      if (req.method() === 'POST') {
        const body = JSON.parse(req.postData() || '{}');
        // After add, list returns [role_1]
        page.route(`**/v1/auth/admin/rbac/users/${USER}/roles?tenant_id=*`, async (route2) => {
          if (await allowOptions(route2, 'GET,OPTIONS')) return;
          return route2.fulfill({ status: 200, body: JSON.stringify({ role_ids: [body.role_id || 'role_1'] }), headers: cors({ 'content-type': 'application/json' }) });
        });
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      if (req.method() === 'DELETE') {
        // After remove, list returns []
        page.route(`**/v1/auth/admin/rbac/users/${USER}/roles?tenant_id=*`, async (route2) => {
          if (await allowOptions(route2, 'GET,OPTIONS')) return;
          return route2.fulfill({ status: 200, body: JSON.stringify({ role_ids: [] }), headers: cors({ 'content-type': 'application/json' }) });
        });
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      return route.fallback();
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=rbac-user-roles`, { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/+admin$/);
    await page.getByTestId('admin-tenant-input').fill(TENANT);

    // List roles
    await page.getByTestId('rbac-user-id').fill(USER);
    await page.getByTestId('rbac-user-roles-list').click();
    await expect(page.getByTestId('rbac-user-roles-empty')).toBeVisible();

    // Add role
    await page.getByTestId('rbac-user-role-id').fill('role_1');
    await page.getByTestId('rbac-user-role-add').click();
    await expect(page.getByTestId('rbac-user-role-item-role_1')).toBeVisible({ timeout: 10000 });

    // Remove role
    await page.getByTestId('rbac-user-role-remove-role_1').click();
    await expect(page.getByTestId('rbac-user-roles-empty')).toBeVisible({ timeout: 10000 });
  });

  test('permissions viewer lists permissions', async ({ page }) => {
    // Mock the permissions endpoint
    await page.route('**/v1/auth/admin/rbac/permissions', async (route) => {
      const req = route.request();
      if (req.method() === 'OPTIONS') {
        return route.fulfill({ status: 204, headers: cors({ 'access-control-allow-methods': 'GET,OPTIONS', 'access-control-allow-headers': 'content-type,authorization,accept,x-guard-client' }) });
      }
      if (req.method() === 'GET') {
        return route.fulfill({
          status: 200,
          body: JSON.stringify({ permissions: [
            { id: 'perm_1', key: 'users.read', description: 'Read users' },
            { id: 'perm_2', key: 'users.write', description: 'Write users' },
          ] }),
          headers: cors({ 'content-type': 'application/json' })
        });
      }
      return route.fallback();
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=rbac-permissions`, { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/+admin$/);

    // Trigger load
    await page.getByTestId('rbac-permissions-refresh').click();
    await expect(page.getByTestId('rbac-permissions-item-perm_1')).toBeVisible({ timeout: 10000 });
    await expect(page.getByTestId('rbac-permissions-item-perm_2')).toBeVisible({ timeout: 10000 });
  });
});
