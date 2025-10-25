import { useCallback, useEffect, useState } from 'react'
import QRCode from 'react-qr-code'
import { Button } from '@/components/ui/button'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'

export default function MyMfaPanel(): React.JSX.Element {
  const [loading, setLoading] = useState<
    'start' | 'activate' | 'disable' | 'generate' | 'count' | null
  >(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [secret, setSecret] = useState<string | null>(null)
  const [otpauth, setOtpauth] = useState<string | null>(null)
  const [count, setCount] = useState<number | null>(null)
  const [code, setCode] = useState('')
  const { show } = useToast()

  async function startTotp() {
    setError(null)
    setMessage(null)
    setLoading('start')
    try {
      const c = getClient()
      const res = await c.mfaStartTotp()
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setSecret((res.data as any)?.secret || null)
        setOtpauth((res.data as any)?.otpauth_url || null)
        setMessage('TOTP secret generated')
        show({ variant: 'success', title: 'TOTP secret generated' })
      } else {
        setError('Failed to start TOTP enrollment')
        show({ variant: 'error', title: 'Failed to start TOTP' })
      }
    } catch (e: any) {
      setError(e?.message || String(e))
      show({
        variant: 'error',
        title: 'Error',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(null)
    }
  }

  async function activateTotp() {
    setError(null)
    setMessage(null)
    setLoading('activate')
    try {
      const c = getClient()
      const res = await c.mfaActivateTotp({ code })
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setMessage('TOTP activated')
        show({ variant: 'success', title: 'TOTP activated' })
      } else {
        setError('Failed to activate TOTP')
        show({ variant: 'error', title: 'Failed to activate TOTP' })
      }
    } catch (e: any) {
      setError(e?.message || String(e))
      show({
        variant: 'error',
        title: 'Error',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(null)
    }
  }

  async function disableTotp() {
    setError(null)
    setMessage(null)
    setLoading('disable')
    try {
      const c = getClient()
      const res = await c.mfaDisableTotp()
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setMessage('TOTP disabled')
        show({ variant: 'success', title: 'TOTP disabled' })
      } else {
        setError('Failed to disable TOTP')
        show({ variant: 'error', title: 'Failed to disable TOTP' })
      }
    } catch (e: any) {
      setError(e?.message || String(e))
      show({
        variant: 'error',
        title: 'Error',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(null)
    }
  }

  async function generateBackup() {
    setError(null)
    setMessage(null)
    setLoading('generate')
    try {
      const c = getClient()
      const res = await c.mfaGenerateBackupCodes({ count: 5 })
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const codes = (res.data as any)?.codes || []
        setMessage(`Generated ${codes.length} codes`)
        show({
          variant: 'success',
          title: 'Backup codes generated',
          description: `${(res.data as any)?.codes?.length ?? 0} codes`
        })
      } else {
        setError('Failed to generate backup codes')
        show({ variant: 'error', title: 'Failed to generate backup codes' })
      }
    } catch (e: any) {
      setError(e?.message || String(e))
      show({
        variant: 'error',
        title: 'Error',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(null)
    }
  }

  const refreshCount = useCallback(async (opts?: { silent?: boolean }) => {
    setError(null)
    setMessage(null)
    setLoading('count')
    try {
      const c = getClient()
      const res = await c.mfaCountBackupCodes()
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setCount((res.data as any)?.count ?? null)
        if (!opts?.silent) {
          show({ variant: 'success', title: 'Backup code count updated' })
        }
      } else {
        setError('Failed to fetch backup count')
        show({ variant: 'error', title: 'Failed to fetch backup count' })
      }
    } catch (e: any) {
      setError(e?.message || String(e))
      show({
        variant: 'error',
        title: 'Error',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(null)
    }
  }, [show])

  useEffect(() => {
    void refreshCount({ silent: true })
  }, [refreshCount])

  return (
    <div className="space-y-3" data-testid="my-mfa">
      <h3 className="text-sm font-medium">My MFA</h3>
      {error && (
        <div
          className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700"
          data-testid="my-mfa-error"
        >
          {error}
        </div>
      )}
      {message && (
        <div
          className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800"
          data-testid="my-mfa-message"
        >
          {message}
        </div>
      )}

      <div className="space-y-2">
        <div className="flex gap-2 flex-wrap">
          <Button
            data-testid="mfa-start"
            onClick={() => startTotp()}
            disabled={loading !== null}
          >
            {loading === 'start' ? 'Starting...' : 'Start TOTP'}
          </Button>
          <input
            data-testid="mfa-code"
            className="rounded-md border px-3 py-2 text-sm"
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <Button
            data-testid="mfa-activate"
            onClick={() => activateTotp()}
            disabled={!code || loading !== null}
          >
            {loading === 'activate' ? 'Activating...' : 'Activate'}
          </Button>
          <Button
            data-testid="mfa-disable"
            variant="secondary"
            onClick={() => disableTotp()}
            disabled={loading !== null}
          >
            {loading === 'disable' ? 'Disabling...' : 'Disable'}
          </Button>
        </div>
        {(secret || otpauth) && (
          <div className="rounded-md border p-2 text-sm">
            {secret && (
              <div>
                <span className="font-medium">Secret:</span>{' '}
                <code data-testid="mfa-secret">{secret}</code>
              </div>
            )}
            {otpauth && (
              <div className="mt-1 break-all">
                <span className="font-medium">otpauth:</span>{' '}
                <span data-testid="mfa-otpauth">{otpauth}</span>
              </div>
            )}
            {otpauth && (
              <div className="mt-3 flex flex-col items-center gap-2">
                <QRCode value={otpauth} size={160} data-testid="mfa-qr" />
                <span className="text-xs text-muted-foreground">
                  Scan this QR code with your authenticator app
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Button
            data-testid="mfa-generate-backup"
            onClick={() => generateBackup()}
            disabled={loading !== null}
          >
            {loading === 'generate' ? 'Generating...' : 'Generate Backup Codes'}
          </Button>
          <Button
            data-testid="mfa-refresh-count"
            variant="secondary"
            onClick={() => refreshCount()}
            disabled={loading !== null}
          >
            {loading === 'count' ? 'Refreshing...' : 'Refresh Count'}
          </Button>
          <div className="text-sm text-muted-foreground">
            Remaining: <span data-testid="mfa-count">{count ?? '-'}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
