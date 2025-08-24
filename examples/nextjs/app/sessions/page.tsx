"use client";

import { useEffect, useState } from 'react';

type Session = {
  id: string;
  revoked: boolean;
  user_agent: string;
  ip: string;
  created_at: string;
  expires_at: string;
};

type SessionsResp = { sessions: Session[] };

export default function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [canSeeAll, setCanSeeAll] = useState(false);
  const [showAll, setShowAll] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const url = showAll ? '/api/sessions?all=1' : '/api/sessions';
      const r = await fetch(url, { cache: 'no-store' });
      const j: SessionsResp | any = await r.json();
      if (!r.ok) throw new Error(j?.error || `Failed: ${r.status}`);
      setSessions(Array.isArray((j as any)?.sessions) ? (j as any).sessions : []);
    } catch (e: any) {
      setError(e?.message || 'failed');
    } finally {
      setLoading(false);
    }
  }

  async function loadProfile() {
    try {
      const r = await fetch('/api/me', { cache: 'no-store' });
      const j = await r.json();
      if (r.ok) {
        const roles: string[] = Array.isArray(j?.data?.roles) ? j.data.roles : [];
        setCanSeeAll(roles.includes('admin') || roles.includes('owner'));
      }
    } catch {}
  }

  async function revoke(id: string) {
    setError(null); setInfo(null);
    const r = await fetch(`/api/sessions/${encodeURIComponent(id)}/revoke`, { method: 'POST' });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      setError(j?.error || `Revoke failed: ${r.status}`);
      return;
    }
    setInfo('Session revoked');
    await load();
  }

  useEffect(() => { loadProfile(); load(); }, []);
  useEffect(() => { load(); }, [showAll]);

  return (
    <div className="card" data-testid="sessions">
      <h2>My Sessions</h2>
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <a href="/" style={{ textDecoration: 'underline' }}>Home</a>
        <a href="/admin/users" style={{ textDecoration: 'underline' }}>Admin Users</a>
        {canSeeAll && (
          <label style={{ marginLeft: 8 }}>
            <input
              type="checkbox"
              checked={showAll}
              onChange={(e) => setShowAll(e.target.checked)}
              style={{ marginRight: 4 }}
            />
            Show all sessions
          </label>
        )}
      </div>
      {loading && <p>Loading...</p>}
      {error && <p style={{ color: '#b91c1c' }}>Error: {error}</p>}
      {info && <p style={{ color: '#065f46' }}>{info}</p>}
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left' }}>ID</th>
            <th style={{ textAlign: 'left' }}>User Agent</th>
            <th style={{ textAlign: 'left' }}>IP</th>
            <th style={{ textAlign: 'left' }}>Created</th>
            <th style={{ textAlign: 'left' }}>Expires</th>
            <th style={{ textAlign: 'left' }}>Revoked</th>
            <th style={{ textAlign: 'left' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.id}>
              <td style={{ padding: '4px 8px' }}><code style={{ fontSize: 12 }}>{s.id}</code></td>
              <td style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.user_agent}</td>
              <td>{s.ip}</td>
              <td>{new Date(s.created_at).toLocaleString()}</td>
              <td>{new Date(s.expires_at).toLocaleString()}</td>
              <td>{s.revoked ? 'yes' : 'no'}</td>
              <td>
                {!s.revoked && <button onClick={() => revoke(s.id)}>Revoke</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
