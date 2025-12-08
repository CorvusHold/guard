import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'
import { Loader2, CheckCircle, XCircle } from 'lucide-react'

type VerifyState = 'verifying' | 'success' | 'error'

export default function MagicLinkVerify() {
  const [state, setState] = useState<VerifyState>('verifying')
  const [error, setError] = useState<string | null>(null)
  const { show } = useToast()

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')
    let redirectTimeout: ReturnType<typeof setTimeout> | null = null

    if (!token) {
      setState('error')
      setError('Missing magic link token')
      return
    }

    async function verify() {
      try {
        const client = getClient()
        const res = await client.magicVerify({ token: token! })

        if (res.meta.status === 200) {
          setState('success')
          show({ variant: 'success', title: 'Signed in successfully' })
          // Redirect to admin after a short delay
          redirectTimeout = setTimeout(() => {
            window.location.href = '/admin'
          }, 1500)
        } else {
          const errMsg = (res.data as any)?.error || 'Magic link verification failed'
          setState('error')
          setError(errMsg)
          show({ variant: 'error', title: 'Verification failed', description: errMsg })
        }
      } catch (err: any) {
        const errMsg = err?.message || String(err)
        setState('error')
        setError(errMsg)
        show({ variant: 'error', title: 'Error', description: errMsg })
      }
    }

    verify()

    return () => {
      if (redirectTimeout) clearTimeout(redirectTimeout)
    }
  }, [show])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-md space-y-4 rounded-xl border p-6 text-center">
        {state === 'verifying' && (
          <>
            <Loader2 className="mx-auto h-12 w-12 animate-spin text-blue-600" />
            <h1 className="text-xl font-semibold">Verifying magic link...</h1>
            <p className="text-sm text-muted-foreground">
              Please wait while we sign you in.
            </p>
          </>
        )}

        {state === 'success' && (
          <>
            <CheckCircle className="mx-auto h-12 w-12 text-green-600" />
            <h1 className="text-xl font-semibold">Signed in successfully!</h1>
            <p className="text-sm text-muted-foreground">
              Redirecting you to the dashboard...
            </p>
          </>
        )}

        {state === 'error' && (
          <>
            <XCircle className="mx-auto h-12 w-12 text-red-600" />
            <h1 className="text-xl font-semibold">Verification failed</h1>
            <p className="text-sm text-muted-foreground">
              {error || 'The magic link is invalid or has expired.'}
            </p>
            <div className="flex justify-center gap-2">
              <Button onClick={() => { window.location.href = '/' }}>
                Back to login
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
