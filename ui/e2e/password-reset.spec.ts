import { expect, test } from '@playwright/test'

const API_URL = 'http://localhost:5173'

async function setupRuntime(page: import('@playwright/test').Page) {
  await page.goto(
    `/?guard-base-url=${encodeURIComponent(API_URL)}&source=redirect`
  )
  await expect(page.getByTestId('configured-base-url')).toHaveText(API_URL)
}

test.describe('Password Reset Flow', () => {
  test.describe('Forgot Password Page', () => {
    test('displays forgot password form', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/forgot-password')
      await expect(page.getByRole('heading', { name: 'Reset your password' })).toBeVisible()
      await expect(page.getByTestId('forgot-password-email')).toBeVisible()
      await expect(page.getByTestId('forgot-password-submit')).toBeVisible()
    })

    test('submit button is disabled when email is empty', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/forgot-password')
      await expect(page.getByTestId('forgot-password-submit')).toBeDisabled()
    })

    test('submit button is enabled when email is entered', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/forgot-password')
      await page.getByTestId('forgot-password-email').fill('test@example.com')
      await expect(page.getByTestId('forgot-password-submit')).toBeEnabled()
    })

    test('navigates back to login', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/forgot-password')
      await page.getByRole('button', { name: 'Back to login' }).click()
      await expect(page).toHaveURL('/')
    })
  })

  test.describe('Reset Password Page', () => {
    test('displays reset password form with token', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/reset-password?token=test-token-123')
      await expect(page.getByRole('heading', { name: 'Set new password' })).toBeVisible()
      await expect(page.getByTestId('reset-password-password')).toBeVisible()
      await expect(page.getByTestId('reset-password-confirm')).toBeVisible()
      await expect(page.getByTestId('reset-password-submit')).toBeVisible()
    })

    test('shows error when no token provided', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/reset-password')
      await expect(page.getByRole('heading', { name: 'Invalid reset link' })).toBeVisible()
    })

    test('validates password match', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/reset-password?token=test-token-123')
      await page.getByTestId('reset-password-password').fill('NewPassword123!')
      await page.getByTestId('reset-password-confirm').fill('DifferentPassword!')
      await page.getByTestId('reset-password-submit').click()
      await expect(page.getByTestId('reset-password-error')).toContainText('Passwords do not match')
    })

    test('validates password length', async ({ page }) => {
      await setupRuntime(page)
      await page.goto('/reset-password?token=test-token-123')
      await page.getByTestId('reset-password-password').fill('short')
      await page.getByTestId('reset-password-confirm').fill('short')
      await page.getByTestId('reset-password-submit').click()
      await expect(page.getByTestId('reset-password-error')).toContainText('at least 8 characters')
    })
  })
})
