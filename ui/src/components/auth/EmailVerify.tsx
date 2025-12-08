import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { useToast } from '@/lib/toast'
import { Loader2, CheckCircle, XCircle, Mail } from 'lucide-react'

type VerifyState = 'verifying' | 'success' | 'error' | 'no-token'

export default function EmailVerify() {
  const [state, setState] = useState<VerifyState>('verifying')
  const [error, setError] = useState<string | null>(null)
  const { show } = useToast()

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')

    if (!token) {
      setState('no-token')
      return
    }

    // TODO: Implement email verification API call when backend is ready
    // For now, show a placeholder message
    async function verify() {
      try {
        // Placeholder - backend email verification endpoint needs to be implemented
        // const client = getClient()
        // const res = await client.verifyEmail({ token })
        
        // Simulate verification for now
        await new Promise(resolve => setTimeout(resolve, 1500))
        
        // For now, show error since backend isn't implemented
        setState('error')
        setError('Email verification is not yet implemented. Please contact support.')
      } catch (err: any) {
        const errMsg = err?.message || String(err)
        setState('error')
        setError(errMsg)
        show({ variant: 'error', title: 'Error', description: errMsg })
      }
    }

    verify()
  }, [show])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-6">
      <div className="w-full max-w-md space-y-4 rounded-xl border p-6 text-center">
        {state === 'verifying' && (
          <>
            <Loader2 className="mx-auto h-12 w-12 animate-spin text-blue-600" />
            <h1 className="text-xl font-semibold">Verifying your email...</h1>
            <p className="text-sm text-muted-foreground">
              Please wait while we verify your email address.
            </p>
          </>
        )}

        {state === 'success' && (
          <>
            <CheckCircle className="mx-auto h-12 w-12 text-green-600" />
            <h1 className="text-xl font-semibold">Email verified!</h1>
            <p className="text-sm text-muted-foreground">
              Your email address has been verified. You can now sign in.
            </p>
            <Button onClick={() => { window.location.href = '/' }}>
              Go to login
            </Button>
          </>
        )}

        {state === 'error' && (
          <>
            <XCircle className="mx-auto h-12 w-12 text-red-600" />
            <h1 className="text-xl font-semibold">Verification failed</h1>
            <p className="text-sm text-muted-foreground">
              {error || 'The verification link is invalid or has expired.'}
            </p>
            <div className="flex justify-center gap-2">
              <Button onClick={() => { window.location.href = '/' }}>
                Back to login
              </Button>
            </div>
          </>
        )}

        {state === 'no-token' && (
          <>
            <Mail className="mx-auto h-12 w-12 text-gray-400" />
            <h1 className="text-xl font-semibold">No verification token</h1>
            <p className="text-sm text-muted-foreground">
              This page is used to verify your email address. Please use the link sent to your email.
            </p>
            <Button onClick={() => { window.location.href = '/' }}>
              Back to login
            </Button>
          </>
        )}
      </div>
    </div>
  )
}
