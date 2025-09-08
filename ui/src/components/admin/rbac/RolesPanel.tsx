import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { getClient } from '@/lib/sdk';

export type RoleItem = {
  id: string;
  name: string;
  description?: string;
  tenant_id: string;
};

export default function RolesPanel({ tenantId }: { tenantId: string }) {
  const [roles, setRoles] = useState<RoleItem[]>([]);
  const [loading, setLoading] = useState<null | 'list' | 'create' | 'update' | 'delete'>(null);
  const [error, setError] = useState<string | null>(null);

  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');

  async function loadRoles() {
    setError(null);
    if (!tenantId) { setError('tenant_id is required'); return; }
    setLoading('list');
    try {
      const res = await getClient().rbacListRoles({ tenant_id: tenantId });
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const list = Array.isArray((res.data as any)?.roles) ? (res.data as any).roles : [];
        setRoles(list as RoleItem[]);
      } else {
        setError('Failed to list roles');
      }
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(null);
    }
  }

  useEffect(() => {
    // do not auto-load without tenantId
  }, [tenantId]);

  async function createRole() {
    setError(null);
    if (!tenantId) { setError('tenant_id is required'); return; }
    if (!newName.trim()) { setError('name is required'); return; }
    setLoading('create');
    try {
      const res = await getClient().rbacCreateRole({ tenant_id: tenantId, name: newName.trim(), description: newDesc || undefined } as any);
      if (res.meta.status >= 200 && res.meta.status < 400) {
        setNewName('');
        setNewDesc('');
        await loadRoles();
      } else {
        setError('Failed to create role');
      }
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(null);
    }
  }

  async function updateRole(r: RoleItem, patch: { name?: string; description?: string }) {
    setError(null);
    if (!tenantId) { setError('tenant_id is required'); return; }
    setLoading('update');
    try {
      const res = await getClient().rbacUpdateRole(r.id, { tenant_id: tenantId, name: patch.name ?? r.name, description: patch.description ?? r.description } as any);
      if (res.meta.status >= 200 && res.meta.status < 400) {
        await loadRoles();
      } else {
        setError('Failed to update role');
      }
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(null);
    }
  }

  async function deleteRole(id: string) {
    setError(null);
    if (!tenantId) { setError('tenant_id is required'); return; }
    setLoading('delete');
    try {
      const res = await getClient().rbacDeleteRole(id, { tenant_id: tenantId });
      if (res.meta.status >= 200 && res.meta.status < 400) {
        await loadRoles();
      } else {
        setError('Failed to delete role');
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
        <h3 className="text-sm font-medium">Roles</h3>
        <Button data-testid="rbac-roles-refresh" variant="secondary" onClick={loadRoles} disabled={loading!==null}>Refresh</Button>
      </div>
      {error && <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="rbac-roles-error">{error}</div>}

      <div className="rounded-md border p-3 space-y-2">
        <div className="text-sm font-medium">Create Role</div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <input data-testid="rbac-role-new-name" className="w-full rounded-md border px-3 py-2 text-sm" placeholder="name" value={newName} onChange={(e)=>setNewName(e.target.value)} />
          <input data-testid="rbac-role-new-desc" className="w-full rounded-md border px-3 py-2 text-sm" placeholder="description (optional)" value={newDesc} onChange={(e)=>setNewDesc(e.target.value)} />
          <Button data-testid="rbac-role-create" onClick={createRole} disabled={loading!==null}>Create</Button>
        </div>
      </div>

      <div className="rounded-md border p-3 space-y-2">
        <div className="text-sm font-medium">Existing Roles</div>
        {roles.length === 0 ? (
          <div className="text-sm text-muted-foreground" data-testid="rbac-roles-empty">No roles</div>
        ) : (
          <div className="space-y-2">
            {roles.map((r)=> (
              <div key={r.id} className="grid grid-cols-1 md:grid-cols-4 gap-2 items-center" data-testid={`rbac-role-item-${r.id}`}>
                <div className="text-xs text-muted-foreground break-all">{r.id}</div>
                <input className="w-full rounded-md border px-2 py-1 text-sm" defaultValue={r.name} onBlur={(e)=>{ const v = e.target.value; if (v!==r.name) void updateRole(r, { name: v }); }} />
                <input className="w-full rounded-md border px-2 py-1 text-sm" defaultValue={r.description || ''} onBlur={(e)=>{ const v = e.target.value; if (v!== (r.description||'')) void updateRole(r, { description: v }); }} />
                <div className="flex gap-2">
                  <Button variant="destructive" onClick={()=>deleteRole(r.id)} data-testid={`rbac-role-delete-${r.id}`} disabled={loading!==null}>Delete</Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
