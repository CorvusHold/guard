import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Shield, CheckCircle, XCircle, Globe, User, Mail, RefreshCw } from 'lucide-react'
import { getClient } from '@/lib/sdk'

interface ScopeDetail {
  scope: string
  description: string
}

interface ConsentData {
  consent_required: boolean
  client: {
    name: string
    logo_uri?: string
  }
  scopes: ScopeDetail[]
  consent_challenge: string
  client_id: string
  redirect_uri: string
  response_type: string
  scope: string
  state: string
  nonce: string
  code_challenge: string
  code_challenge_method: string
}

interface OAuthConsentProps {
  consentData: ConsentData
  onComplete?: () => void
}

const scopeIcons: Record<string, React.ReactNode> = {
  openid: <Shield className="h-5 w-5 text-blue-500" />,
  profile: <User className="h-5 w-5 text-green-500" />,
  email: <Mail className="h-5 w-5 text-purple-500" />,
  offline_access: <RefreshCw className="h-5 w-5 text-orange-500" />,
}

export default function OAuthConsent({ consentData, onComplete }: OAuthConsentProps) {
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleDecision(approved: boolean) {
    setSubmitting(true)
    setError(null)

    try {
      const client = getClient()
      const baseUrl = (client as any).baseUrl || ''

      const resp = await fetch(`${baseUrl}/oauth/authorize/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          approved,
          consent_challenge: consentData.consent_challenge,
          client_id: consentData.client_id,
          redirect_uri: consentData.redirect_uri,
          response_type: consentData.response_type,
          scope: consentData.scope,
          state: consentData.state,
          nonce: consentData.nonce,
          code_challenge: consentData.code_challenge,
          code_challenge_method: consentData.code_challenge_method,
        }),
        redirect: 'manual',
      })

      if (resp.type === 'opaqueredirect' || resp.status === 302) {
        const location = resp.headers.get('Location')
        if (location) {
          window.location.href = location
          return
        }
      }

      if (resp.ok) {
        const data = await resp.json()
        if (data.redirect_uri) {
          window.location.href = data.redirect_uri
          return
        }
      }

      if (!approved) {
        setError('Authorization denied.')
      } else {
        setError('Unexpected response from server.')
      }
    } catch (err) {
      setError('Failed to process authorization request.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-4" data-testid="oauth-consent-screen">
      <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        {/* Header */}
        <div className="px-6 pt-6 pb-4 text-center border-b border-gray-100 dark:border-gray-700">
          {consentData.client.logo_uri ? (
            <img
              src={consentData.client.logo_uri}
              alt={consentData.client.name}
              className="h-16 w-16 mx-auto mb-3 rounded-lg object-contain"
              data-testid="oauth-client-logo"
            />
          ) : (
            <div className="h-16 w-16 mx-auto mb-3 rounded-lg bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
              <Globe className="h-8 w-8 text-blue-600 dark:text-blue-400" />
            </div>
          )}
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white" data-testid="oauth-client-name">
            {consentData.client.name}
          </h2>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            wants to access your account
          </p>
        </div>

        {/* Scopes */}
        <div className="px-6 py-4">
          <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            This application will be able to:
          </p>
          <ul className="space-y-3" data-testid="oauth-scopes-list">
            {consentData.scopes.map((s) => (
              <li key={s.scope} className="flex items-center gap-3" data-testid={`oauth-scope-${s.scope}`}>
                {scopeIcons[s.scope] || <CheckCircle className="h-5 w-5 text-gray-400" />}
                <span className="text-sm text-gray-700 dark:text-gray-300">{s.description}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Error */}
        {error && (
          <div className="px-6 pb-2">
            <p className="text-sm text-red-600 dark:text-red-400" data-testid="oauth-consent-error">{error}</p>
          </div>
        )}

        {/* Actions */}
        <div className="px-6 pb-6 pt-2 flex gap-3">
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => handleDecision(false)}
            disabled={submitting}
            data-testid="oauth-deny-btn"
          >
            <XCircle className="h-4 w-4 mr-2" />
            Deny
          </Button>
          <Button
            className="flex-1"
            onClick={() => handleDecision(true)}
            disabled={submitting}
            data-testid="oauth-approve-btn"
          >
            <CheckCircle className="h-4 w-4 mr-2" />
            {submitting ? 'Authorizing...' : 'Authorize'}
          </Button>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-gray-50 dark:bg-gray-900 border-t border-gray-100 dark:border-gray-700">
          <p className="text-xs text-center text-gray-400">
            Authorizing will redirect you to{' '}
            <span className="font-mono text-gray-500">{new URL(consentData.redirect_uri).origin}</span>
          </p>
        </div>
      </div>
    </div>
  )
}
