import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { getClient } from '@/lib/sdk';
import { useToast } from '@/lib/toast';
import { Skeleton } from '@/components/ui/skeleton';

interface ACLPanelProps {
  tenantId: string;
}

export default function ACLPanel({ tenantId }: ACLPanelProps): React.JSX.Element {
  const [subjectType, setSubjectType] = useState<'user' | 'group'>('user');
  const [subjectId, setSubjectId] = useState('');
  const [permissionKey, setPermissionKey] = useState('');
  const [objectType, setObjectType] = useState('');
  const [objectId, setObjectId] = useState('');
  const [loading, setLoading] = useState<'create' | 'delete' | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { show } = useToast();

  const canSubmit = !!tenantId && !!subjectType && !!subjectId && !!permissionKey && !!objectType;

  async function createTuple() {
    setMessage(null); setError(null);
    if (!canSubmit) { setError('All required fields must be set'); return; }
    setLoading('create');
    try {
      const c = getClient();
      const res = await c.fgaCreateAclTuple({
        tenant_id: tenantId,
        subject_type: subjectType,
        subject_id: subjectId,
        permission_key: permissionKey,
        object_type: objectType,
        object_id: objectId.trim() ? objectId.trim() : null,
      });
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setMessage('ACL tuple created');
        show({ variant: 'success', title: 'ACL tuple created' });
      } else {
        setError('Failed to create ACL tuple');
        show({ variant: 'error', title: 'Create failed' });
      }
    } catch (e: any) {
      setError(e?.message || String(e));
      show({ variant: 'error', title: 'Error', description: e?.message || String(e) });
    } finally {
      setLoading(null);
    }
  }

  async function deleteTuple() {
    setMessage(null); setError(null);
    if (!canSubmit) { setError('All required fields must be set'); return; }
    setLoading('delete');
    try {
      const c = getClient();
      const res = await c.fgaDeleteAclTuple({
        tenant_id: tenantId,
        subject_type: subjectType,
        subject_id: subjectId,
        permission_key: permissionKey,
        object_type: objectType,
        object_id: objectId.trim() ? objectId.trim() : null,
      });
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setMessage('ACL tuple deleted');
        show({ variant: 'success', title: 'ACL tuple deleted' });
      } else {
        setError('Failed to delete ACL tuple');
        show({ variant: 'error', title: 'Delete failed' });
      }
    } catch (e: any) {
      setError(e?.message || String(e));
      show({ variant: 'error', title: 'Error', description: e?.message || String(e) });
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="space-y-3" data-testid="fga-acl">
      <h3 className="text-sm font-medium">ACL Tuples</h3>
      {loading && <Skeleton className="h-4 w-full" />}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-2">
        <select
          data-testid="fga-acl-subject-type"
          className="w-full rounded-md border px-3 py-2 text-sm"
          value={subjectType}
          onChange={(e) => setSubjectType((e.target.value as 'user' | 'group') || 'user')}
        >
          <option value="user">user</option>
          <option value="group">group</option>
        </select>
        <input
          data-testid="fga-acl-subject-id"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="Subject ID"
          value={subjectId}
          onChange={(e) => setSubjectId(e.target.value)}
        />
        <input
          data-testid="fga-acl-permission-key"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="Permission key (e.g. users.read)"
          value={permissionKey}
          onChange={(e) => setPermissionKey(e.target.value)}
        />
        <input
          data-testid="fga-acl-object-type"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="Object type (e.g. tenant, doc)"
          value={objectType}
          onChange={(e) => setObjectType(e.target.value)}
        />
        <input
          data-testid="fga-acl-object-id"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="Object ID (optional)"
          value={objectId}
          onChange={(e) => setObjectId(e.target.value)}
        />
        <div className="flex gap-2">
          <Button data-testid="fga-acl-create" onClick={() => createTuple()} disabled={!canSubmit || loading !== null}>
            {loading === 'create' ? 'Creating...' : 'Create'}
          </Button>
          <Button data-testid="fga-acl-delete" variant="destructive" onClick={() => deleteTuple()} disabled={!canSubmit || loading !== null}>
            {loading === 'delete' ? 'Deleting...' : 'Delete'}
          </Button>
        </div>
      </div>
      {error && (<div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="fga-acl-error">{error}</div>)}
      {message && (<div className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800" data-testid="fga-acl-message">{message}</div>)}
      <div className="text-xs text-muted-foreground">Note: Tenant ID is taken from the field at the top of this page.</div>
    </div>
  );
}
