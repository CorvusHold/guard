"use client";

import { useEffect, useState } from "react";

type MeResponse = {
  data?: any;
  meta: { status: number };
  error?: any;
};

export default function ProtectedPage() {
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function fetchMe() {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/me", { cache: "no-store" });
      const j: MeResponse = await r.json();
      if (r.ok) setProfile(j.data);
      else setError(j.error || `Me failed: ${j.meta?.status}`);
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setLoading(false);
    }
  }

  async function onLogout() {
    setLoading(true);
    setError(null);
    try {
      // Navigate to GET /api/logout which clears cookies and redirects to '/'
      window.location.href = "/api/logout";
      return;
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchMe();
  }, []);

  return (
    <div className="card" data-testid="protected">
      <h2>Protected Area</h2>
      <p>This page is protected by middleware and requires a valid session.</p>
      {profile ? (
        <>
          <pre style={{ whiteSpace: "pre-wrap" }} data-testid="profile-json">{JSON.stringify(profile, null, 2)}</pre>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={fetchMe} disabled={loading} data-testid="btn-refresh-profile">Refresh Profile</button>
            <button onClick={onLogout} disabled={loading} data-testid="btn-logout">Logout</button>
            <a href="/" data-testid="link-home">Home</a>
          </div>
        </>
      ) : (
        <p>Loading...</p>
      )}
      {error && <p style={{ color: "#b91c1c", marginTop: 12 }}>Error: {error}</p>}
    </div>
  );
}
