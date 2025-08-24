"use client";

import { useEffect, useState } from 'react';

type AdminUser = {
  id: string;
  first_name: string;
  last_name: string;
  roles: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at?: string | null;
};

type AdminUsersResp = { users: AdminUser[] };

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [edit, setEdit] = useState<Record<string, { first_name: string; last_name: string }>>({});
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newFirst, setNewFirst] = useState('');
  const [newLast, setNewLast] = useState('');
  const [creating, setCreating] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/admin/users', { cache: 'no-store' });
      const j: AdminUsersResp | any = await r.json();
      if (!r.ok) throw new Error(j?.error || `Failed: ${r.status}`);
      const list = Array.isArray((j as any)?.users) ? (j as any).users : [];
      setUsers(list);
      // seed edit map
      const m: Record<string, { first_name: string; last_name: string }> = {};
      for (const u of list) m[u.id] = { first_name: u.first_name ?? '', last_name: u.last_name ?? '' };
      setEdit(m);
    } catch (e: any) {
      setError(e?.message || 'failed');
    } finally {
      setLoading(false);
    }
  }

  async function updateNames(id: string) {
    setError(null); setInfo(null);
    try {
      const body = edit[id];
      const r = await fetch(`/api/admin/users/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.error || `Update failed: ${r.status}`);
      }
      setInfo('Updated');
      await load();
    } catch (e: any) {
      setError(e?.message || 'failed');
    }
  }

  async function block(id: string) {
    setError(null); setInfo(null);
    const r = await fetch(`/api/admin/users/${encodeURIComponent(id)}/block`, { method: 'POST' });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      setError(j?.error || `Block failed: ${r.status}`);
      return;
    }
    setInfo('User blocked');
    await load();
  }

  async function unblock(id: string) {
    setError(null); setInfo(null);
    const r = await fetch(`/api/admin/users/${encodeURIComponent(id)}/unblock`, { method: 'POST' });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      setError(j?.error || `Unblock failed: ${r.status}`);
      return;
    }
    setInfo('User unblocked');
    await load();
  }

  async function createUser(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setError(null); setInfo(null);
    setCreating(true);
    try {
      const r = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: newEmail, password: newPassword, first_name: newFirst, last_name: newLast }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j?.error || `Create failed: ${r.status}`);
      setInfo('User created');
      setNewEmail(''); setNewPassword(''); setNewFirst(''); setNewLast('');
      await load();
    } catch (e: any) {
      setError(e?.message || 'failed');
    } finally {
      setCreating(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <div className="card" data-testid="admin-users">
      <h2>Admin • Users</h2>
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <a href="/" style={{ textDecoration: 'underline' }}>Home</a>
        <a href="/sessions" style={{ textDecoration: 'underline' }}>Sessions</a>
      </div>
      <form onSubmit={createUser} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', margin: '8px 0' }}>
        <input placeholder="Email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} />
        <input placeholder="Password" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
        <input placeholder="First name" value={newFirst} onChange={(e) => setNewFirst(e.target.value)} />
        <input placeholder="Last name" value={newLast} onChange={(e) => setNewLast(e.target.value)} />
        <button type="submit" disabled={creating || !newEmail || !newPassword}>{creating ? 'Creating...' : 'Create user'}</button>
      </form>
      {loading && <p>Loading...</p>}
      {error && <p style={{ color: '#b91c1c' }}>Error: {error}</p>}
      {info && <p style={{ color: '#065f46' }}>{info}</p>}
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left' }}>ID</th>
            <th style={{ textAlign: 'left' }}>First</th>
            <th style={{ textAlign: 'left' }}>Last</th>
            <th style={{ textAlign: 'left' }}>Roles</th>
            <th style={{ textAlign: 'left' }}>Active</th>
            <th style={{ textAlign: 'left' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td style={{ padding: '4px 8px' }}><code style={{ fontSize: 12 }}>{u.id}</code></td>
              <td>
                <input
                  value={edit[u.id]?.first_name ?? ''}
                  onChange={(e) => setEdit((m) => ({ ...m, [u.id]: { ...m[u.id], first_name: e.target.value } }))}
                  placeholder="First"
                />
              </td>
              <td>
                <input
                  value={edit[u.id]?.last_name ?? ''}
                  onChange={(e) => setEdit((m) => ({ ...m, [u.id]: { ...m[u.id], last_name: e.target.value } }))}
                  placeholder="Last"
                />
              </td>
              <td>{Array.isArray(u.roles) ? u.roles.join(', ') : ''}</td>
              <td>{u.is_active ? 'yes' : 'no'}</td>
              <td style={{ display: 'flex', gap: 6 }}>
                <button onClick={() => updateNames(u.id)}>Save</button>
                {u.is_active ? (
                  <button onClick={() => block(u.id)}>Block</button>
                ) : (
                  <button onClick={() => unblock(u.id)}>Unblock</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
