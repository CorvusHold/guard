import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { getClient } from '@/lib/sdk'
import { useTenant } from '@/lib/tenant'
import { useToast } from '@/lib/toast'

export default function ResetPassword() {
  const [token, setToken] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { tenantId } = useTenant()
  const { show } = useToast()

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const t = params.get('token')
    if (t) setToken(t)
  }, [])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!token || !password) return
    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    setError(null)
    setLoading(true)
    try {
      const client = getClient()
      const res = await client.passwordResetConfirm({
        tenant_id: tenantId || undefined,
        token,
        new_password: password
      })
      if (res.meta.status === 200) {
        setSuccess(true)
        show({ variant: 'success', title: 'Password reset successful' })
      } else {
        const errMsg = (res.data as any)?.error || 'Failed to reset password'
        setError(errMsg)
        show({ variant: 'error', title: 'Failed to reset password', description: errMsg })
      }
    } catch (err: any) {
      const errMsg = err?.message || String(err)
      setError(errMsg)
      show({ variant: 'error', title: 'Error', description: errMsg })
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
          <h1 className="text-xl font-semibold">Password reset successful</h1>
          <p className="text-sm text-muted-foreground">
            Your password has been reset. You can now log in with your new password.
          </p>
          <Button onClick={() => { window.location.href = '/' }}>
            Go to login
          </Button>
        </div>
      </div>
    )
  }

  if (!token) {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center p-6">
        <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
          <h1 className="text-xl font-semibold">Invalid reset link</h1>
          <p className="text-sm text-muted-foreground">
            This password reset link is invalid or has expired. Please request a new one.
          </p>
          <div className="flex gap-2">
            <Button onClick={() => { window.location.href = '/forgot-password' }}>
              Request new link
            </Button>
            <Button variant="secondary" onClick={() => { window.location.href = '/' }}>
              Back to login
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-md space-y-4 rounded-xl border p-6">
        <h1 className="text-xl font-semibold">Set new password</h1>
        <p className="text-sm text-muted-foreground">
          Enter your new password below.
        </p>
        {error && (
          <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="reset-password-error">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="password">New password</Label>
            <Input
              id="password"
              type="password"
              data-testid="reset-password-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Minimum 8 characters"
              required
              autoFocus
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm">Confirm password</Label>
            <Input
              id="confirm"
              type="password"
              data-testid="reset-password-confirm"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm your password"
              required
            />
          </div>
          <div className="flex gap-2">
            <Button
              type="submit"
              data-testid="reset-password-submit"
              disabled={loading || !password || !confirmPassword}
            >
              {loading ? 'Resetting...' : 'Reset password'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => { window.location.href = '/' }}
            >
              Cancel
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
