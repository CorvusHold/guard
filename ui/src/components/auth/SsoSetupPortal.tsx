import { useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { ensureRuntimeConfigFromQuery, getRuntimeConfig } from '@/lib/runtime'
import { getClient } from '@/lib/sdk'
import type { SsoPortalSessionResp, SsoProviderItem } from '../../../../sdk/ts/src/client'

export default function SsoSetupPortal() {
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [message, setMessage] = useState<string>('')
  const [session, setSession] = useState<SsoPortalSessionResp | null>(null)
  const [provider, setProvider] = useState<SsoProviderItem | null>(null)

  // Capture token on first render, before any URL cleanup
  const tokenRef = useRef<string | null>(null)
  if (tokenRef.current === null) {
    try {
      const usp = new URLSearchParams(window.location.search)
      tokenRef.current = usp.get('token')?.trim() || ''
    } catch {
      tokenRef.current = ''
    }
  }

  // Use ref to ensure we only process the token once (handles React strict mode double-invoke)
  const processedRef = useRef(false)

  useEffect(() => {
    // Persist runtime config from query when arriving via portal link
    ensureRuntimeConfigFromQuery()

    // Skip if already processed (React strict mode protection)
    if (processedRef.current) return
    processedRef.current = true

    async function run() {
      const token = tokenRef.current || ''
      if (!token) {
        setStatus('error')
        setMessage('Missing portal token in URL')
        return
      }

      // Verify runtime config is present before calling getClient()
      const runtimeConfig = getRuntimeConfig()
      if (!runtimeConfig) {
        setStatus('error')
        setMessage('Runtime config missing from portal query (guard-base-url required)')
        return
      }

      setStatus('loading')
      try {
        const client = getClient()
        const ctx = await client.loadSsoPortalContext(token)
        if (!ctx?.session || !ctx?.provider) {
          setStatus('error')
          setMessage('Failed to load portal context')
          return
        }
        setSession(ctx.session)
        setProvider(ctx.provider)
        setStatus('success')
        setMessage('Portal session established')

        // Clean token from URL to limit leakage
        try {
          const url = new URL(window.location.href)
          url.searchParams.delete('token')
          window.history.replaceState({}, '', url.toString())
        } catch {
          // ignore cleanup errors
        }
      } catch (e: unknown) {
        setStatus('error')
        const errMsg = e instanceof Error ? e.message : 'Unknown error'
        setMessage(`Portal session failed: ${errMsg}`)
      }
    }

    void run()
  }, [])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-2xl space-y-4 rounded-xl border p-6">
        <h1 className="text-xl font-semibold">SSO Setup Portal</h1>
        {status === 'loading' && (
          <div className="text-sm text-muted-foreground" data-testid="sso-setup-loading">
            Validating portal link and loading provider configuration...
          </div>
        )}
        {status === 'error' && (
          <div className="space-y-2">
            <div
              className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700"
              data-testid="sso-setup-error"
            >
              {message}
            </div>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                onClick={() => {
                  window.location.href = '/'
                }}
              >
                Back to login
              </Button>
            </div>
          </div>
        )}
        {status === 'success' && session && provider && (
          <div className="space-y-4" data-testid="sso-setup-success">
            <div className="rounded-md border p-3 text-sm">
              <div className="font-medium">Portal Context</div>
              <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                <div>
                  <span className="font-semibold">Tenant ID:</span> {session.tenant_id}
                </div>
                <div>
                  <span className="font-semibold">Portal Token ID:</span> {session.portal_token_id}
                </div>
                <div>
                  <span className="font-semibold">Intent:</span> {session.intent}
                </div>
              </div>
            </div>
            <div className="rounded-md border p-3 text-sm">
              <div className="font-medium">Provider</div>
              <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                <div>
                  <span className="font-semibold">Name:</span> {provider.name}
                </div>
                <div>
                  <span className="font-semibold">Slug:</span> {provider.slug}
                </div>
                <div>
                  <span className="font-semibold">Type:</span> {provider.provider_type}
                </div>
                {provider.issuer && (
                  <div>
                    <span className="font-semibold">Issuer:</span> {provider.issuer}
                  </div>
                )}
                {provider.entity_id && (
                  <div>
                    <span className="font-semibold">Entity ID:</span> {provider.entity_id}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
