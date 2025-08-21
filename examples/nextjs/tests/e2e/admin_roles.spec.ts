import { test, expect } from '@playwright/test';
import { loginWithPasswordAndMFA } from '../support/auth';

// E2E: create a user (via backend signup), then assign roles (admin + owner) using admin privileges
// Preconditions:
// - GUARD_BASE_URL and GUARD_TENANT_ID set
// - Admin-capable credentials in env: ADMIN_EMAIL/ADMIN_PASSWORD (or NONMFA_EMAIL/NONMFA_PASSWORD with admin role)
// - If MFA is enabled, provide TOTP_SECRET for admin user
// The test logs in via the app to obtain an access token, then calls backend role update endpoint.

test('admin can create user and assign admin+owner roles', async ({ page, context }) => {
  test.setTimeout(180_000);

  const baseUrl = process.env.GUARD_BASE_URL;
  const tenantId = process.env.GUARD_TENANT_ID;
  if (!baseUrl || !tenantId) {
    test.skip(true, 'GUARD_BASE_URL/GUARD_TENANT_ID not set; skipping');
  }

  const adminEmail = process.env.ADMIN_EMAIL ?? process.env.NONMFA_EMAIL ?? process.env.EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD ?? process.env.NONMFA_PASSWORD ?? process.env.PASSWORD;
  const adminTotp = process.env.ADMIN_TOTP_SECRET ?? process.env.TOTP_SECRET;
  if (!adminEmail || !adminPassword) {
    test.skip(true, 'ADMIN_* or NONMFA_* credentials not set; skipping');
  }

  await context.clearCookies();

  // 1) Login as admin-capable user via the app
  await loginWithPasswordAndMFA(page, { email: adminEmail, password: adminPassword, totpSecret: adminTotp });

  // 2) Fetch current admin access token from cookies
  const cookies = await context.cookies();
  const accessCookie = cookies.find((c) => c.name === 'guard_access_token');
  if (!accessCookie?.value) throw new Error('missing guard_access_token cookie after login');
  const adminAccess = accessCookie.value;

  // 2a) Verify the logged-in user has admin role; otherwise skip to avoid false failure
  const adminIntro = await page.request.post(`${baseUrl}/v1/auth/introspect`, {
    headers: { 'content-type': 'application/json' },
    data: { token: adminAccess },
  });
  expect(adminIntro.ok()).toBeTruthy();
  const adminIntroJson: any = await adminIntro.json();
  const roles: string[] = Array.isArray(adminIntroJson?.roles) ? adminIntroJson.roles : [];
  if (!roles.some((r) => String(r).toLowerCase() === 'admin')) {
    test.skip(true, 'Logged-in test user does not have admin role; skipping');
  }

  // 3) Create a new user directly via backend signup (public endpoint)
  const ts = Date.now();
  const newEmail = `e2e.roles.${ts}@example.com`;
  const newPassword = 'Password!123';
  const newFirst = `E2EFirst_${ts}`;
  const newLast = `E2ELast_${ts}`;

  const signupRes = await page.request.post(`${baseUrl}/v1/auth/password/signup`, {
    headers: { 'content-type': 'application/json' },
    data: { tenant_id: tenantId, email: newEmail, password: newPassword, first_name: newFirst, last_name: newLast },
  });
  expect(signupRes.ok()).toBeTruthy();
  const signupJson: any = await signupRes.json();
  const newAccess: string | undefined = signupJson?.access_token;
  expect(newAccess).toBeTruthy();

  // 4) Determine the new user's id by introspecting the new token
  const introspectRes = await page.request.post(`${baseUrl}/v1/auth/introspect`, {
    headers: { 'content-type': 'application/json' },
    data: { token: newAccess },
  });
  expect(introspectRes.ok()).toBeTruthy();
  const intrJson: any = await introspectRes.json();
  const targetUserId: string | undefined = intrJson?.user_id ?? intrJson?.sub ?? intrJson?.user?.id;
  expect(targetUserId).toBeTruthy();

  // 5) As admin, update the target user's roles to [admin, owner]
  const rolesUpdateRes = await page.request.post(`${baseUrl}/v1/auth/admin/users/${encodeURIComponent(targetUserId!)}/roles`, {
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${adminAccess}`,
    },
    data: { roles: ['admin', 'owner'] },
  });
  expect([204, 200].includes(rolesUpdateRes.status())).toBeTruthy();

  // 6) As admin, navigate to the Admin Users page and verify roles show for the created user
  await page.goto('/admin/users');
  // Verify page visible
  await expect(page.getByTestId('admin-users')).toBeVisible();
  // Look up table row by first/last names
  const row = page.locator('table tbody tr').filter({ hasText: newFirst }).filter({ hasText: newLast });
  await expect(row).toHaveCount(1);
  await expect(row).toContainText('admin');
  await expect(row).toContainText('owner');
});
