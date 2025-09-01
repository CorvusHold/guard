'use client';

import { useState } from 'react';

export default function PortalLinkPage() {
  const [orgId, setOrgId] = useState('');
  const [intent, setIntent] = useState('');
  const [link, setLink] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setLink(null);
    try {
      const params = new URLSearchParams();
      params.set('organization_id', orgId);
      if (intent) params.set('intent', intent);
      const res = await fetch(`/api/sso/workos/portal-link?${params.toString()}`, { method: 'GET' });
      const json = await res.json();
      if (!res.ok) {
        setError(json?.error || `Failed (${res.status})`);
      } else {
        setLink(json?.link || null);
      }
    } catch (e: any) {
      setError(e?.message || 'Unexpected error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 640, margin: '2rem auto', padding: '1rem' }}>
      <h1>WorkOS Organization Portal</h1>
      <p>Generate an admin portal link for a WorkOS organization. Requires you to be logged in as an admin.</p>

      <form onSubmit={handleGenerate} style={{ display: 'grid', gap: '0.75rem', marginTop: '1rem' }}>
        <label style={{ display: 'grid', gap: '0.25rem' }}>
          <span>Organization ID</span>
          <input
            type="text"
            value={orgId}
            onChange={(e) => setOrgId(e.target.value)}
            placeholder="org_01H..."
            required
            style={{ padding: '0.5rem', border: '1px solid #ccc', borderRadius: 4 }}
          />
        </label>
        <label style={{ display: 'grid', gap: '0.25rem' }}>
          <span>Intent (optional)</span>
          <input
            type="text"
            value={intent}
            onChange={(e) => setIntent(e.target.value)}
            placeholder="sso | dsync | user_management | ..."
            style={{ padding: '0.5rem', border: '1px solid #ccc', borderRadius: 4 }}
          />
        </label>
        <button type="submit" disabled={loading || !orgId} style={{ padding: '0.5rem 1rem' }}>
          {loading ? 'Generating…' : 'Generate Link'}
        </button>
      </form>

      {error && (
        <p style={{ color: 'crimson', marginTop: '1rem' }}>
          <strong>Error:</strong> {error}
        </p>
      )}

      {link && (
        <p style={{ marginTop: '1rem' }}>
          <strong>Portal Link:</strong>{' '}
          <a href={link} target="_blank" rel="noreferrer">
            {link}
          </a>
        </p>
      )}
    </div>
  );
}
