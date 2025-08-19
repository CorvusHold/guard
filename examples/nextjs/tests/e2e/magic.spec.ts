import { test, expect } from '@playwright/test';

const EMAIL = 'e2e-magic@example.com';

async function getMagicToken(request: any, email: string, baseURL: string) {
  const res = await request.post('/api/test/magic/token', {
    data: {
      email,
      redirect_url: `${baseURL}/magic/complete`,
    },
  });
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body.token).toBeTruthy();
  return body.token as string;
}

test('magic link end-to-end logs in and accesses protected page', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('baseURL not configured');

  // Visit home
  await page.goto('/');
  await expect(page.getByTestId('home')).toBeVisible();

  // Send magic link
  await page.getByTestId('input-magic-email').fill(EMAIL);
  await page.getByTestId('btn-magic-send').click();
  await expect(page.getByTestId('info')).toContainText('Magic link sent');

  // Fetch deterministic token from test API (bridges to backend test endpoint)
  const token = await getMagicToken(request, EMAIL, baseURL);

  // Verify token in browser context to set httpOnly cookies
  await page.evaluate(async (t) => {
    await fetch(`/api/magic/verify?token=${encodeURIComponent(t)}`);
  }, token);

  // Go to protected page
  await page.goto('/protected');
  await expect(page.getByTestId('protected')).toBeVisible();
  await expect(page.getByTestId('profile-json')).toBeVisible();
});
