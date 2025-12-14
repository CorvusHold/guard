import { useEffect, useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { ensureRuntimeConfigFromQuery } from '@/lib/runtime'
import { getClient } from '@/lib/sdk'

export default function SSOCallback() {
  const [status, setStatus] = useState<
    'idle' | 'loading' | 'success' | 'error'
  >('idle')
  const [message, setMessage] = useState<string>('')
  const [profile, setProfile] = useState<any | null>(null)

  const qp = useMemo(() => new URLSearchParams(window.location.search), [])
  const provider = (qp.get('provider') || '').toLowerCase()
  const code = qp.get('code') || ''
  const state = qp.get('state') || undefined
  const tenantIdFromQuery = qp.get('tenant_id') || undefined

  useEffect(() => {
    // Persist runtime config if guard-base-url is present
    ensureRuntimeConfigFromQuery()

    async function run() {
      if (!provider || !code) {
        setStatus('error')
        setMessage('Missing provider or code in callback URL')
        return
      }
      if (provider !== 'dev' && provider !== 'workos') {
        setStatus('error')
        setMessage(`Unsupported provider: ${provider}`)
        return
      }
      setStatus('loading')
      try {
        const client = getClient()
        let tenant_id = tenantIdFromQuery
        if (!tenant_id) {
          try {
            tenant_id =
              localStorage.getItem('guard_ui:tenant_id') ||
              localStorage.getItem('tenant_id') ||
              undefined
          } catch {
            // ignore
          }
        }
        const res = await client.handleSsoCallback(provider as any, {
          tenant_id,
          code,
          state
        })
        if (res.meta.status === 200) {
          const me = await client.me()
          if (me.meta.status === 200) setProfile(me.data as any)
          setStatus('success')
          setMessage('Sign-in completed')
        } else {
          setStatus('error')
          setMessage('Callback failed')
        }
      } catch (e: any) {
        setStatus('error')
        setMessage(e?.message || String(e))
      }
    }

    void run()
  }, [provider, code, state, tenantIdFromQuery])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-lg space-y-4 rounded-xl border p-6">
        <h1 className="text-xl font-semibold">Completing sign-in...</h1>
        {status === 'loading' && (
          <div className="text-sm text-muted-foreground">
            Processing callback with {provider.toUpperCase()}...
          </div>
        )}
        {status === 'success' && (
          <div className="space-y-2">
            <div className="rounded-md border p-3 text-sm">
              <div className="font-medium">{message}</div>
              {profile && (
                <div className="text-xs text-muted-foreground">
                  Signed in as {(profile as any).email}
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <Button
                onClick={() => {
                  window.location.href = '/'
                }}
              >
                Continue
              </Button>
            </div>
          </div>
        )}
        {status === 'error' && (
          <div className="space-y-2">
            <div
              className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700"
              data-testid="callback-error"
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
      </div>
    </div>
  )
}
