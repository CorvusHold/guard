import { expect, test } from '@playwright/test'

declare const process: { env: Record<string, string | undefined> }

const API_BASE = process.env.SSO_PORTAL_E2E_API_URL ?? 'http://localhost:8081'
const TENANT_ID = process.env.SSO_PORTAL_E2E_TENANT_ID
const ADMIN_TOKEN = process.env.SSO_PORTAL_E2E_ADMIN_TOKEN
const PROVIDER_SLUG = process.env.SSO_PORTAL_E2E_PROVIDER_SLUG

const missingEnv = !TENANT_ID || !ADMIN_TOKEN || !PROVIDER_SLUG

function logMissingEnv() {
  const missing: string[] = []
  if (!TENANT_ID) missing.push('SSO_PORTAL_E2E_TENANT_ID')
  if (!ADMIN_TOKEN) missing.push('SSO_PORTAL_E2E_ADMIN_TOKEN')
  if (!PROVIDER_SLUG) missing.push('SSO_PORTAL_E2E_PROVIDER_SLUG')
  // eslint-disable-next-line no-console
  console.warn(
    `Skipping SSO portal fully wired test: missing env vars: ${missing.join(', ')}`
  )
}

test.describe('SSO Setup Portal (fully wired)', () => {
  test('loads portal context end-to-end using real backend', async ({ page, request }) => {
    if (missingEnv) {
      logMissingEnv()
      test.skip()
    }

    const slug = PROVIDER_SLUG!

    const portalResp = await request.get(
      `${API_BASE}/v1/auth/sso/${encodeURIComponent(slug)}/portal-link`,
      {
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          Accept: 'application/json'
        },
        params: {
          tenant_id: TENANT_ID!,
          intent: 'sso'
        }
      }
    )

    expect(portalResp.ok(), 'portal-link response ok').toBeTruthy()
    const json = (await portalResp.json()) as { link?: string }
    expect(typeof json.link, 'portal-link.link is string').toBe('string')

    const link = json.link as string
    const url = new URL(link)
    expect(url.pathname).toBe('/portal/sso-setup')

    const q = url.searchParams
    const token = q.get('token')
    const guardBase = q.get('guard-base-url')
    const provider = q.get('provider')
    const intent = q.get('intent') || 'sso'

    expect(token, 'portal token present in link').not.toBeNull()
    expect(guardBase, 'guard-base-url present in link').not.toBeNull()
    expect(provider, 'provider slug in link').toBe(slug)
    expect(intent, 'intent in link').toBe('sso')

    // In this test environment the UI runs on a different origin than the API.
    // Rewrite only the origin of the portal link to point at the UI server
    // while preserving the validated path and query parameters.
    const uiBase = process.env.SSO_PORTAL_E2E_UI_URL ?? 'http://localhost:4173'
    const uiUrl = new URL(uiBase)
    url.protocol = uiUrl.protocol
    url.host = uiUrl.host
    const browserLink = url.toString()

    await page.goto(browserLink)

    await page.waitForFunction(() => !!localStorage.getItem('guard_runtime'))

    const success = page.getByTestId('sso-setup-success')
    await expect(success).toBeVisible()

    if (TENANT_ID) {
      await expect(success).toContainText(new RegExp(`Tenant ID:\\s*${TENANT_ID}`))
    }

    await expect(success).toContainText(/Portal Token ID:\s*\S+/)
    await expect(success).toContainText(new RegExp(`Slug:\\s*${slug}`))

    await expect(page.getByTestId('sso-setup-loading')).not.toBeVisible()

    await expect(page).not.toHaveURL(/token=/)
    await expect(page).not.toHaveURL(/guard-base-url=/)
  })
})
