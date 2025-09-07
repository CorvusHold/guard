import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { getClient } from '@/lib/sdk';
import { useToast } from '@/lib/toast';

interface GroupMembersPanelProps {
  groupId: string;
}

export default function GroupMembersPanel({ groupId }: GroupMembersPanelProps): React.JSX.Element {
  const [userId, setUserId] = useState('');
  const [loading, setLoading] = useState<'add' | 'remove' | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { show } = useToast();

  async function onAdd() {
    setMessage(null); setError(null);
    if (!groupId || !userId) { setError('groupId and userId are required'); return; }
    setLoading('add');
    try {
      const c = getClient();
      const res = await c.fgaAddGroupMember(groupId, { user_id: userId });
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setMessage('Member added');
        show({ variant: 'success', title: 'Member added' });
      } else {
        setError('Failed to add member');
        show({ variant: 'error', title: 'Add failed' });
      }
    } catch (e: any) {
      setError(e?.message || String(e));
      show({ variant: 'error', title: 'Error', description: e?.message || String(e) });
    } finally {
      setLoading(null);
    }
  }

  async function onRemove() {
    setMessage(null); setError(null);
    if (!groupId || !userId) { setError('groupId and userId are required'); return; }
    setLoading('remove');
    try {
      const c = getClient();
      const res = await c.fgaRemoveGroupMember(groupId, { user_id: userId });
      if (res.meta.status >= 200 && res.meta.status < 300) {
        setMessage('Member removed');
        show({ variant: 'success', title: 'Member removed' });
      } else {
        setError('Failed to remove member');
        show({ variant: 'error', title: 'Remove failed' });
      }
    } catch (e: any) {
      setError(e?.message || String(e));
      show({ variant: 'error', title: 'Error', description: e?.message || String(e) });
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="space-y-3" data-testid="fga-members">
      <h3 className="text-sm font-medium">Group Members</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <input
          data-testid="fga-member-user-id"
          className="w-full rounded-md border px-3 py-2 text-sm"
          placeholder="User ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
        />
        <Button data-testid="fga-member-add" onClick={() => onAdd()} disabled={!userId || !groupId || loading !== null}>
          {loading === 'add' ? 'Adding...' : 'Add Member'}
        </Button>
        <Button data-testid="fga-member-remove" variant="destructive" onClick={() => onRemove()} disabled={!userId || !groupId || loading !== null}>
          {loading === 'remove' ? 'Removing...' : 'Remove Member'}
        </Button>
      </div>
      {error && (<div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="fga-members-error">{error}</div>)}
      {message && (<div className="rounded-md border border-green-200 bg-green-50 p-2 text-sm text-green-800" data-testid="fga-members-message">{message}</div>)}
    </div>
  );
}
