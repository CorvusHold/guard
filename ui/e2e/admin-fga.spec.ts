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

test.describe('Admin FGA (Groups, Members, ACL)', () => {
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

  test('FGA errors show banners and toasts', async ({ page }) => {
    const TENANT = 'tenant_fga';

    // Mock admin user for tab visibility
    await page.route('**/v1/auth/me', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 200, body: JSON.stringify({ 
        email: 'admin@example.com', 
        first_name: 'Admin', 
        last_name: 'User',
        roles: ['admin']
      }), headers: cors({ 'content-type': 'application/json' }) });
    });

    // Groups list -> 500
    await page.route('**/v1/auth/admin/fga/groups?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 500, body: JSON.stringify({ message: 'server error' }), headers: cors({ 'content-type': 'application/json' }) });
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=fga`, { waitUntil: 'domcontentloaded' });
    
    // Wait for admin user to load and tabs to render
    await page.waitForSelector('[data-testid="tab-fga"]', { timeout: 10000 });
    
    await page.getByTestId('admin-tenant-input').fill(TENANT);

    // Trigger refresh and expect error banner
    await page.getByTestId('fga-groups-refresh').click();
    await expect(page.getByTestId('fga-groups-error')).toBeVisible();

    // ACL create -> 400
    await page.route('**/v1/auth/admin/fga/acl/tuples', async (route) => {
      if (await allowOptions(route, 'POST,DELETE,OPTIONS')) return;
      const req = route.request();
      if (req.method() === 'POST') {
        return route.fulfill({ status: 400, body: JSON.stringify({ message: 'bad request' }), headers: cors({ 'content-type': 'application/json' }) });
      }
      return route.fallback();
    });
    await page.getByTestId('fga-acl-subject-type').selectOption('user');
    await page.getByTestId('fga-acl-subject-id').fill('u_err');
    await page.getByTestId('fga-acl-permission-key').fill('users.read');
    await page.getByTestId('fga-acl-object-type').fill('tenant');
    await page.getByTestId('fga-acl-object-id').fill(TENANT);
    await page.getByTestId('fga-acl-create').click();
    await expect(page.getByTestId('fga-acl-error')).toBeVisible();
  });

  test('groups CRUD, membership add/remove, ACL create/delete', async ({ page }) => {
    const TENANT = 'tenant_fga';

    // Mock admin user for tab visibility
    await page.route('**/v1/auth/me', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 200, body: JSON.stringify({ 
        email: 'admin@example.com', 
        first_name: 'Admin', 
        last_name: 'User',
        roles: ['admin']
      }), headers: cors({ 'content-type': 'application/json' }) });
    });

    // Initial groups empty, then reflect created
    await page.route('**/v1/auth/admin/fga/groups?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 200, body: JSON.stringify({ groups: [] }), headers: cors({ 'content-type': 'application/json' }) });
    });
    await page.route('**/v1/auth/admin/fga/groups', async (route) => {
      if (await allowOptions(route, 'POST,OPTIONS')) return;
      const req = route.request();
      if (req.method() === 'POST') {
        const body = JSON.parse(req.postData() || '{}');
        const created = { id: 'g_1', tenant_id: body.tenant_id, name: body.name, description: body.description || null, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
        // After create -> list shows item
        page.route('**/v1/auth/admin/fga/groups?tenant_id=*', async (route2) => {
          if (await allowOptions(route2, 'GET,OPTIONS')) return;
          return route2.fulfill({ status: 200, body: JSON.stringify({ groups: [created] }), headers: cors({ 'content-type': 'application/json' }) });
        });
        return route.fulfill({ status: 201, body: JSON.stringify(created), headers: cors({ 'content-type': 'application/json' }) });
      }
      return route.fallback();
    });
    await page.route('**/v1/auth/admin/fga/groups/g_1?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'DELETE,OPTIONS')) return;
      // After delete -> list returns empty
      page.route('**/v1/auth/admin/fga/groups?tenant_id=*', async (route2) => {
        if (await allowOptions(route2, 'GET,OPTIONS')) return;
        return route2.fulfill({ status: 200, body: JSON.stringify({ groups: [] }), headers: cors({ 'content-type': 'application/json' }) });
      });
      return route.fulfill({ status: 204, headers: cors({}) });
    });

    // Group members add/remove
    await page.route('**/v1/auth/admin/fga/groups/g_1/members', async (route) => {
      if (await allowOptions(route, 'POST,DELETE,OPTIONS')) return;
      const req = route.request();
      if (req.method() === 'POST') {
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      if (req.method() === 'DELETE') {
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      return route.fallback();
    });

    // ACL create/delete
    await page.route('**/v1/auth/admin/fga/acl/tuples', async (route) => {
      if (await allowOptions(route, 'POST,DELETE,OPTIONS')) return;
      const req = route.request();
      if (req.method() === 'POST') {
        const created = { id: 't_1' };
        return route.fulfill({ status: 201, body: JSON.stringify(created), headers: cors({ 'content-type': 'application/json' }) });
      }
      if (req.method() === 'DELETE') {
        return route.fulfill({ status: 204, headers: cors({}) });
      }
      return route.fallback();
    });

    await page.goto(`${UI_BASE}/admin?guard-base-url=${encodeURIComponent(UI_BASE)}&source=fga`, { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/+admin$/);

    // Wait for admin user to load and tabs to render
    await page.waitForSelector('[data-testid="tab-fga"]', { timeout: 10000 });

    // Enter tenant and load
    await page.getByTestId('admin-tenant-input').fill(TENANT);

    // Create group
    await page.getByTestId('fga-group-name').fill('team-alpha');
    await page.getByTestId('fga-group-desc').fill('Alpha team');
    await page.getByTestId('fga-group-create').click();
    await expect(page.getByTestId('fga-groups')).toContainText('team-alpha', { timeout: 10000 });

    // Add and remove member
    await page.getByTestId('fga-members-group-id').fill('g_1');
    await page.getByTestId('fga-member-user-id').fill('u_42');
    await page.getByTestId('fga-member-add').click();
    await expect(page.getByTestId('fga-members-message')).toHaveText(/added/i, { timeout: 10000 });

    await page.getByTestId('fga-member-remove').click();
    await expect(page.getByTestId('fga-members-message')).toHaveText(/removed/i, { timeout: 10000 });

    // Create/delete ACL tuple
    await page.getByTestId('fga-acl-subject-type').selectOption('user');
    await page.getByTestId('fga-acl-subject-id').fill('u_42');
    await page.getByTestId('fga-acl-permission-key').fill('users.read');
    await page.getByTestId('fga-acl-object-type').fill('tenant');
    await page.getByTestId('fga-acl-object-id').fill(TENANT);
    await page.getByTestId('fga-acl-create').click();
    await expect(page.getByTestId('fga-acl-message')).toHaveText(/created/i, { timeout: 10000 });

    await page.getByTestId('fga-acl-delete').click();
    await expect(page.getByTestId('fga-acl-message')).toHaveText(/deleted/i, { timeout: 10000 });

    // Delete group
    await page.route('**/v1/auth/admin/fga/groups?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'GET,OPTIONS')) return;
      return route.fulfill({ status: 200, body: JSON.stringify({ groups: [
        { id: 'g_1', tenant_id: TENANT, name: 'team-alpha', description: 'Alpha team', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      ] }), headers: cors({ 'content-type': 'application/json' }) });
    });

    // Confirm delete path invoked
    await page.route('**/v1/auth/admin/fga/groups/g_1?tenant_id=*', async (route) => {
      if (await allowOptions(route, 'DELETE,OPTIONS')) return;
      // After delete -> list empty
      page.route('**/v1/auth/admin/fga/groups?tenant_id=*', async (route2) => {
        if (await allowOptions(route2, 'GET,OPTIONS')) return;
        return route2.fulfill({ status: 200, body: JSON.stringify({ groups: [] }), headers: cors({ 'content-type': 'application/json' }) });
      });
      return route.fulfill({ status: 204, headers: cors({}) });
    });

    // Click delete button in table, then confirm in modal
    const deleteButton = page.getByRole('button', { name: 'Delete' }).first();
    await deleteButton.click();
    // Confirm modal delete
    await page.getByRole('button', { name: 'Delete' }).last().click();
    await expect(page.getByTestId('fga-groups-empty')).toBeVisible({ timeout: 10000 });
  });
});
