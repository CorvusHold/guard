import { useEffect, useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { getClient } from '@/lib/sdk';

interface UsersPanelProps {
  tenantId: string;
}

interface AdminUserItem {
  id: string;
  email_verified: boolean;
  is_active: boolean;
  first_name: string;
  last_name: string;
  roles: string[];
  created_at: string;
  updated_at: string;
  last_login_at?: string | null;
}

export default function UsersPanel({ tenantId }: UsersPanelProps): React.JSX.Element {
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<AdminUserItem[]>([]);

  const canLoad = useMemo(() => !!tenantId, [tenantId]);

  async function load() {
    setError(null);
    if (!canLoad) { setError('tenant_id is required'); return; }
    setLoading(true);
    try {
      const c = getClient();
      const res = await c.listUsers({ tenant_id: tenantId });
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const list = (res.data as any)?.users ?? [];
        setUsers(list as AdminUserItem[]);
      } else {
        setError('Failed to load users');
      }
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { if (tenantId) { void load(); } }, [tenantId]);

  async function onToggleActive(u: AdminUserItem) {
    setError(null);
    try {
      const c = getClient();
      if (u.is_active) {
        await c.blockUser(u.id);
      } else {
        await c.unblockUser(u.id);
      }
      await load();
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  }

  async function onEditNames(u: AdminUserItem) {
    const first = prompt('First name', u.first_name ?? '');
    if (first === null) return;
    const last = prompt('Last name', u.last_name ?? '');
    if (last === null) return;
    setError(null);
    try {
      const c = getClient();
      await c.updateUserNames(u.id, { first_name: first, last_name: last });
      await load();
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Users</h3>
        <div className="flex gap-2">
          <Button data-testid="users-refresh" variant="secondary" onClick={() => load()} disabled={loading || !canLoad}>
            {loading ? 'Loading...' : 'Refresh'}
          </Button>
        </div>
      </div>
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="users-error">{error}</div>
      )}
      {!users.length && !loading ? (
        <div className="text-sm text-muted-foreground">No users found.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="py-2 pr-3">Name</th>
                <th className="py-2 pr-3">Email Verified</th>
                <th className="py-2 pr-3">Active</th>
                <th className="py-2 pr-3">Roles</th>
                <th className="py-2 pr-3">Last Login</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b last:border-b-0" data-testid={`users-item-${u.id}`}>
                  <td className="py-2 pr-3">
                    <div className="font-medium">{u.first_name} {u.last_name}</div>
                    <div className="text-xs text-muted-foreground">{u.id}</div>
                  </td>
                  <td className="py-2 pr-3">{u.email_verified ? 'yes' : 'no'}</td>
                  <td className="py-2 pr-3">
                    <span className={u.is_active ? 'text-green-600' : 'text-red-600'}>
                      {u.is_active ? 'active' : 'blocked'}
                    </span>
                  </td>
                  <td className="py-2 pr-3">{(u.roles || []).join(', ')}</td>
                  <td className="py-2 pr-3">{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '-'}</td>
                  <td className="py-2 pr-3">
                    <div className="flex gap-2">
                      <Button data-testid={`users-edit-${u.id}`} variant="secondary" size="sm" onClick={() => onEditNames(u)}>Edit</Button>
                      <Button data-testid={`users-toggle-${u.id}`} variant={u.is_active ? 'destructive' : 'secondary'} size="sm" onClick={() => onToggleActive(u)}>
                        {u.is_active ? 'Block' : 'Unblock'}
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
