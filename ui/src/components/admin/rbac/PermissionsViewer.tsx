import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { getClient } from '@/lib/sdk';

type PermissionItem = {
  id?: string;
  key?: string;
  description?: string;
  created_at?: string;
  updated_at?: string;
};

export default function PermissionsViewer() {
  const [perms, setPerms] = useState<PermissionItem[]>([]);
  const [loading, setLoading] = useState<null | 'list'>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setError(null);
    setLoading('list');
    try {
      const res = await getClient().rbacListPermissions();
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const list = Array.isArray((res.data as any)?.permissions) ? (res.data as any).permissions : [];
        setPerms(list as PermissionItem[]);
      } else {
        setError('Failed to load permissions');
      }
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Permissions</h3>
        <Button data-testid="rbac-permissions-refresh" variant="secondary" onClick={load} disabled={loading!==null}>Refresh</Button>
      </div>
      {error && <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="rbac-permissions-error">{error}</div>}

      <div className="rounded-md border p-3 space-y-2">
        {perms.length === 0 ? (
          <div className="text-sm text-muted-foreground" data-testid="rbac-permissions-empty">No permissions loaded. Click Refresh.</div>
        ) : (
          <div className="space-y-2">
            {perms.map((p)=> (
              <div key={p.id || p.key} className="grid grid-cols-1 md:grid-cols-3 gap-2 items-start" data-testid={`rbac-permissions-item-${p.id || p.key}`}>
                <div className="text-xs font-mono break-all">{p.key}</div>
                <div className="text-xs text-muted-foreground break-all">{p.description || ''}</div>
                <div className="text-[10px] text-muted-foreground">{p.id}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
