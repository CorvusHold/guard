import { useCallback, useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { getClient } from '@/lib/sdk'
import { useToast } from '@/lib/toast'

interface SessionItem {
  id: string
  revoked: boolean
  user_agent: string
  ip: string
  created_at: string
  expires_at: string
}

export default function MySessionsPanel(): React.JSX.Element {
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const { show } = useToast()

  const load = useCallback(async () => {
    setError(null)
    setLoading(true)
    try {
      const c = getClient()
      const res = await c.listSessions()
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const list = (res.data as any)?.sessions ?? []
        setSessions(list as SessionItem[])
      } else {
        setError('Failed to load sessions')
        show({ variant: 'error', title: 'Failed to load sessions' })
      }
    } catch (e: any) {
      setError(e?.message || String(e))
      show({
        variant: 'error',
        title: 'Error',
        description: e?.message || String(e)
      })
    } finally {
      setLoading(false)
    }
  }, [show])

  useEffect(() => {
    void load()
  }, [load])

  async function revoke(id: string) {
    setError(null)
    try {
      const c = getClient()
      const res = await c.revokeSession(id)
      if (res.meta.status === 204) {
        await load()
        show({ variant: 'success', title: 'Session revoked' })
      } else {
        setError('Failed to revoke session')
        show({ variant: 'error', title: 'Failed to revoke session' })
      }
    } catch (e: any) {
      setError(e?.message || String(e))
      show({
        variant: 'error',
        title: 'Error',
        description: e?.message || String(e)
      })
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">My Sessions</h3>
        <Button
          variant="secondary"
          onClick={() => {
            if (!loading) {
              void load()
            }
          }}
          disabled={loading}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </Button>
      </div>
      {error && (
        <div
          className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700"
          data-testid="sessions-error"
        >
          {error}
        </div>
      )}
      {!sessions.length && !loading ? (
        <div className="text-sm text-muted-foreground">No active sessions.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="py-2 pr-3">User Agent</th>
                <th className="py-2 pr-3">IP</th>
                <th className="py-2 pr-3">Created</th>
                <th className="py-2 pr-3">Expires</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id} className="border-b last:border-b-0">
                  <td className="py-2 pr-3">{s.user_agent || '-'}</td>
                  <td className="py-2 pr-3">{s.ip || '-'}</td>
                  <td className="py-2 pr-3">
                    {s.created_at
                      ? new Date(s.created_at).toLocaleString()
                      : '-'}
                  </td>
                  <td className="py-2 pr-3">
                    {s.expires_at
                      ? new Date(s.expires_at).toLocaleString()
                      : '-'}
                  </td>
                  <td className="py-2 pr-3">
                    <span
                      className={s.revoked ? 'text-red-600' : 'text-green-600'}
                    >
                      {s.revoked ? 'revoked' : 'active'}
                    </span>
                  </td>
                  <td className="py-2 pr-3">
                    <Button
                      variant="destructive"
                      size="sm"
                      disabled={s.revoked}
                      onClick={() => revoke(s.id)}
                    >
                      Revoke
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
