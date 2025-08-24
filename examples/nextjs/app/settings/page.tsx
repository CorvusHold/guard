"use client";

import { useEffect, useMemo, useState } from "react";

type MeResponse = {
  data?: {
    id: string;
    tenant_id: string;
    email: string;
    first_name: string;
    last_name: string;
    roles: string[];
  } | null;
  meta?: { status: number };
  error?: string;
};

type SettingsResponse = {
  sso_provider: string;
  workos_client_id: string;
  workos_client_secret?: string; // masked
  workos_api_key?: string; // masked
  workos_default_connection_id?: string;
  workos_default_organization_id?: string;
  sso_state_ttl: string;
  sso_redirect_allowlist: string;
};

export default function SettingsPage() {
  const [profile, setProfile] = useState<MeResponse["data"]>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // Form state
  const [ssoProvider, setSsoProvider] = useState("");
  const [workosClientId, setWorkosClientId] = useState("");
  const [workosClientSecret, setWorkosClientSecret] = useState("");
  const [workosApiKey, setWorkosApiKey] = useState("");
  const [workosDefaultConnectionId, setWorkosDefaultConnectionId] = useState("");
  const [workosDefaultOrganizationId, setWorkosDefaultOrganizationId] = useState("");
  const [ssoStateTTL, setSsoStateTTL] = useState("");
  const [redirectAllowlist, setRedirectAllowlist] = useState("");

  const isOwner = useMemo(() => !!profile && Array.isArray(profile.roles) && profile.roles.includes("owner"), [profile]);

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      setError(null);
      try {
        // Load profile
        const mr = await fetch("/api/me", { cache: "no-store" });
        const mj: MeResponse = await mr.json();
        if (!mr.ok) throw new Error(mj.error || `me failed: ${mr.status}`);
        setProfile(mj.data || null);

        const tenantId = mj.data?.tenant_id;
        if (!tenantId) throw new Error("missing tenant_id in profile");

        // Load tenant settings
        const sr = await fetch(`/api/tenants/${tenantId}/settings`, { cache: "no-store" });
        const sj: SettingsResponse | { error?: string } = await sr.json();
        if (!sr.ok) throw new Error((sj as any).error || `settings failed: ${sr.status}`);

        const s = sj as SettingsResponse;
        setSsoProvider(s.sso_provider || "");
        setWorkosClientId(s.workos_client_id || "");
        setWorkosDefaultConnectionId(s.workos_default_connection_id || "");
        setWorkosDefaultOrganizationId(s.workos_default_organization_id || "");
        setSsoStateTTL(s.sso_state_ttl || "");
        setRedirectAllowlist(s.sso_redirect_allowlist || "");
        // Do not prefill secrets; show masked values as placeholders
      } catch (e: any) {
        setError(e?.message || "failed");
      } finally {
        setLoading(false);
      }
    };
    init();
  }, []);

  async function onSave(e: React.FormEvent) {
    e.preventDefault();
    if (!profile?.tenant_id) return;
    setError(null);
    setInfo(null);
    setLoading(true);
    try {
      const payload: any = {};
      // Only include non-empty fields; backend treats missing fields as no-op
      if (ssoProvider) payload.sso_provider = ssoProvider;
      if (workosClientId) payload.workos_client_id = workosClientId;
      if (workosDefaultConnectionId) payload.workos_default_connection_id = workosDefaultConnectionId;
      if (workosDefaultOrganizationId) payload.workos_default_organization_id = workosDefaultOrganizationId;
      if (ssoStateTTL) payload.sso_state_ttl = ssoStateTTL;
      if (redirectAllowlist) payload.sso_redirect_allowlist = redirectAllowlist;
      // Only include secrets if provided to avoid clearing
      if (workosClientSecret) payload.workos_client_secret = workosClientSecret;
      if (workosApiKey) payload.workos_api_key = workosApiKey;

      const r = await fetch(`/api/tenants/${profile.tenant_id}/settings`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (r.status === 204) {
        setInfo("Settings saved.");
        // Clear secret inputs after save
        setWorkosClientSecret("");
        setWorkosApiKey("");
      } else {
        const j = await r.json();
        throw new Error(j?.error || `Save failed: ${r.status}`);
      }
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setLoading(false);
    }
  }

  if (loading && !profile) return <div className="card"><p>Loading...</p></div>;

  if (!profile) {
    return (
      <div className="card">
        <h2>Not authenticated</h2>
        <a href="/">Go Home</a>
      </div>
    );
  }

  if (!isOwner) {
    return (
      <div className="card">
        <h2>Forbidden</h2>
        <p>You must be an owner to access Settings.</p>
        <a href="/protected">Go to Protected</a>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Tenant Settings</h2>
      <p style={{ marginTop: 0, color: '#6b7280' }}>Manage SSO and tenant configuration</p>
      <form onSubmit={onSave} style={{ display: 'grid', gap: 12 }}>
        <fieldset style={{ border: '1px solid #e5e7eb', padding: 12 }}>
          <legend>SSO</legend>
          <label htmlFor="sso_provider">SSO Provider</label>
          <select id="sso_provider" value={ssoProvider} onChange={(e) => setSsoProvider(e.target.value)}>
            <option value="">(disabled)</option>
            <option value="dev">Dev</option>
            <option value="workos">WorkOS</option>
          </select>

          <label htmlFor="workos_client_id">WorkOS Client ID</label>
          <input id="workos_client_id" value={workosClientId} onChange={(e) => setWorkosClientId(e.target.value)} placeholder="org_client_..." />

          <label htmlFor="workos_client_secret">WorkOS Client Secret</label>
          <input id="workos_client_secret" type="password" value={workosClientSecret} onChange={(e) => setWorkosClientSecret(e.target.value)} placeholder="leave blank to keep existing" />

          <label htmlFor="workos_api_key">WorkOS API Key</label>
          <input id="workos_api_key" type="password" value={workosApiKey} onChange={(e) => setWorkosApiKey(e.target.value)} placeholder="leave blank to keep existing" />

          <label htmlFor="workos_default_connection_id">Default WorkOS Connection ID (optional)</label>
          <input id="workos_default_connection_id" value={workosDefaultConnectionId} onChange={(e) => setWorkosDefaultConnectionId(e.target.value)} placeholder="conn_..." />

          <label htmlFor="workos_default_organization_id">Default WorkOS Organization ID (optional)</label>
          <input id="workos_default_organization_id" value={workosDefaultOrganizationId} onChange={(e) => setWorkosDefaultOrganizationId(e.target.value)} placeholder="org_..." />

          <label htmlFor="sso_state_ttl">SSO State TTL (e.g., 15m)</label>
          <input id="sso_state_ttl" value={ssoStateTTL} onChange={(e) => setSsoStateTTL(e.target.value)} placeholder="15m" />

          <label htmlFor="redirect_allowlist">Redirect Allowlist (comma-separated URLs)</label>
          <textarea id="redirect_allowlist" rows={3} value={redirectAllowlist} onChange={(e) => setRedirectAllowlist(e.target.value)} placeholder="https://app.example.com, https://localhost:3000" />
        </fieldset>

        <div style={{ display: 'flex', gap: 8 }}>
          <button type="submit" disabled={loading}>Save</button>
          <a href="/protected">Back</a>
        </div>
      </form>

      {info && <p style={{ color: '#065f46', marginTop: 12 }}>{info}</p>}
      {error && <p style={{ color: '#b91c1c', marginTop: 12 }}>Error: {error}</p>}
    </div>
  );
}
