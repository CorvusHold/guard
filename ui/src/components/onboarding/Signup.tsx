import { useEffect, useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { getClient } from '@/lib/sdk'
import { useTenant } from '@/lib/tenant'

export default function Signup() {
  const { tenantId, setTenantId } = useTenant()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [tenant, setTenant] = useState<string>('')
  const [loading, setLoading] = useState<null | 'signup'>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    try {
      const usp = new URLSearchParams(window.location.search)
      const e = usp.get('email') || ''
      const t = usp.get('tenant_id') || ''
      if (e) setEmail(e)
      if (t) setTenant(t)
      else if (tenantId) setTenant(tenantId)
    } catch {}
  }, [tenantId])

  const canSubmit = useMemo(() => {
    return email.trim().length > 0 && password.trim().length >= 8 && tenant.trim().length > 0
  }, [email, password, tenant])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit) return
    setError(null)
    setLoading('signup')
    try {
      const client = getClient()
      const res = await client.passwordSignup({
        tenant_id: tenant.trim(),
        email: email.trim(),
        password: password.trim(),
        first_name: firstName.trim() || undefined,
        last_name: lastName.trim() || undefined
      })
      if (!(res.meta.status >= 200 && res.meta.status < 300)) {
        throw new Error('Failed to create account')
      }
      setTenantId(tenant.trim())
      try {
        window.location.href = '/admin?source=users'
      } catch {}
    } catch (e: any) {
      setError(e?.message || String(e))
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-xl space-y-4 rounded-xl border p-6">
        <h1 className="text-xl font-semibold">Create your account</h1>
        <div className="text-sm text-muted-foreground">
          Join your organization by creating an account.
        </div>
        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="signup-error">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="tenant">Tenant ID</Label>
            <Input id="tenant" data-testid="signup-tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="tenant_uuid" required />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="first">First name</Label>
              <Input id="first" data-testid="signup-first" value={firstName} onChange={(e) => setFirstName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="last">Last name</Label>
              <Input id="last" data-testid="signup-last" value={lastName} onChange={(e) => setLastName(e.target.value)} />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="email">Work email</Label>
            <Input id="email" data-testid="signup-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor="pw">Password</Label>
            <Input id="pw" data-testid="signup-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <div className="text-xs text-muted-foreground">Minimum 8 characters</div>
          </div>
          <div className="flex gap-2">
            <Button type="submit" data-testid="signup-submit" disabled={!canSubmit || loading !== null}>
              {loading === 'signup' ? 'Creating...' : 'Create account'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              data-testid="signup-back"
              onClick={() => { try { window.location.href = '/' } catch {} }}
            >
              Back
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
