import { useEffect, useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { getClient } from '@/lib/sdk';
import { useToast } from '@/lib/toast';
import { Modal } from '@/components/ui/modal';
import { Skeleton } from '@/components/ui/skeleton';

interface GroupsPanelProps {
  tenantId: string;
}

interface FgaGroup {
  id: string;
  tenant_id: string;
  name: string;
  description?: string | null;
  created_at: string;
  updated_at: string;
}

export default function GroupsPanel({ tenantId }: GroupsPanelProps): React.JSX.Element {
  const [loading, setLoading] = useState<boolean>(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [groups, setGroups] = useState<FgaGroup[]>([]);
  const { show } = useToast();
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');

  const canLoad = useMemo(() => !!tenantId, [tenantId]);

  async function load() {
    setMessage(null); setError(null);
    if (!canLoad) { setError('tenant_id is required'); return; }
    setLoading(true);
    try {
      const c = getClient();
      const res = await c.fgaListGroups({ tenant_id: tenantId });
      if (res.meta.status >= 200 && res.meta.status < 300) {
        const list = (res.data as any)?.groups ?? [];
        setGroups(list as FgaGroup[]);
        show({ variant: 'success', title: 'Groups refreshed' });
      } else {
        setError('Failed to load groups');
        show({ variant: 'error', title: 'Failed to load groups' });
      }
    } catch (e: any) {
      setError(e?.message || String(e));
      show({ variant: 'error', title: 'Error', description: e?.message || String(e) });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { if (tenantId) { void load(); } }, [tenantId]);

  async function onCreate() {
    setMessage(null); setError(null);
    if (!newName.trim()) { setError('Group name is required'); return; }
    try {
      const c = getClient();
      await c.fgaCreateGroup({ tenant_id: tenantId, name: newName.trim(), description: newDesc.trim() || null });
      setNewName(''); setNewDesc('');
      setMessage('Group created');
      show({ variant: 'success', title: 'Group created' });
      await load();
    } catch (e: any) {
      setError(e?.message || String(e));
      show({ variant: 'error', title: 'Create failed', description: e?.message || String(e) });
    }
  }

  async function onDelete(id: string) {
    setMessage(null); setError(null);
    try {
      const c = getClient();
      if (!id) return;
      await c.fgaDeleteGroup(id, { tenant_id: tenantId });
      setMessage('Group deleted');
      show({ variant: 'success', title: 'Group deleted' });
      await load();
    } catch (e: any) {
      setError(e?.message || String(e));
      show({ variant: 'error', title: 'Delete failed', description: e?.message || String(e) });
    }
  }

  return (
    <div className="space-y-3" data-testid="fga-groups">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Groups</h3>
        <div className="flex gap-2">
          <Button data-testid="fga-groups-refresh" variant="secondary" onClick={() => load()} disabled={loading || !canLoad}>
            {loading ? 'Loading...' : 'Refresh'}
          </Button>
        </div>
      </div>
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="fga-groups-error">{error}</div>
      )}
      {message && (
        <div className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800" data-testid="fga-groups-message">{message}</div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <input
          data-testid="fga-group-name"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="Group name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
        />
        <input
          data-testid="fga-group-desc"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="Description (optional)"
          value={newDesc}
          onChange={(e) => setNewDesc(e.target.value)}
        />
        <Button data-testid="fga-group-create" onClick={() => onCreate()} disabled={!newName.trim()}>Create</Button>
      </div>
      {loading ? (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="py-2 pr-3">Name</th>
                <th className="py-2 pr-3">Description</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {[1,2,3].map((i) => (
                <tr key={i} className="border-b last:border-b-0">
                  <td className="py-2 pr-3"><Skeleton className="h-4 w-40" /></td>
                  <td className="py-2 pr-3"><Skeleton className="h-4 w-64" /></td>
                  <td className="py-2 pr-3"><Skeleton className="h-8 w-24" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : !groups.length ? (
        <div className="text-sm text-muted-foreground" data-testid="fga-groups-empty">No groups found.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="py-2 pr-3">Name</th>
                <th className="py-2 pr-3">Description</th>
                <th className="py-2 pr-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.id} className="border-b last:border-b-0" data-testid={`fga-group-item-${g.id}`}>
                  <td className="py-2 pr-3">{g.name}</td>
                  <td className="py-2 pr-3">{g.description || '-'}</td>
                  <td className="py-2 pr-3">
                    <Button variant="destructive" size="sm" onClick={() => setDeletingId(g.id)}>Delete</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal open={!!deletingId} title="Delete Group" onClose={() => setDeletingId(null)}>
        <div className="space-y-2">
          <div className="text-sm">Are you sure you want to delete this group?</div>
          <div className="pt-2 text-right">
            <Button size="sm" variant="secondary" className="mr-2" onClick={() => setDeletingId(null)}>Cancel</Button>
            <Button size="sm" variant="destructive" onClick={() => { const id = deletingId!; setDeletingId(null); void onDelete(id); }}>Delete</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
