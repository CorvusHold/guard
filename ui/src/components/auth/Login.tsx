import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { getClient } from "@/lib/sdk";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [tenants, setTenants] = useState<Array<{ id: string; name?: string }>>([]);
  const [needsTenant, setNeedsTenant] = useState(false);
  const [loading, setLoading] = useState<"password" | "sso-dev" | "sso-workos" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [me, setMe] = useState<any | null>(null);
  const [mfa, setMfa] = useState<{ challenge_token: string } | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  useEffect(() => {
    // Clear tenants when email changes
    setTenants([]);
    if (!tenantId) setNeedsTenant(false);
  }, [email]);

  async function handlePasswordLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMfa(null);
    setLoading("password");
    try {
      const client = getClient();
      const res = await client.passwordLogin({ email, password, tenant_id: tenantId || undefined });
      if (res.meta.status === 202) {
        // MFA challenge
        // eslint-disable-next-line no-console
        console.log('LOGIN passwordLogin -> MFA 202 received', res.data);
        setMfa((res.data as any));
        return;
      }
      if (res.meta.status >= 200 && res.meta.status < 300) {
        // eslint-disable-next-line no-console
        console.log('LOGIN passwordLogin -> tokens received, fetching profile');
        const meRes = await client.me();
        if (meRes.meta.status === 200) setMe(meRes.data as any);
      } else if (res.meta.status === 400 || res.meta.status === 422) {
        // Heuristic: if backend requires tenant selection, surface input
        setNeedsTenant(true);
        setError("Tenant required. Please specify a tenant ID.");
        // Attempt discovery if not already done
        if (email) {
          void onDiscoverTenants();
        }
      } else {
        setError("Login failed. Check your credentials.");
      }
    } catch (err: any) {
      // eslint-disable-next-line no-console
      console.error('LOGIN passwordLogin error', err);
      const msg = err?.message || String(err);
      if (/tenant/i.test(msg)) setNeedsTenant(true);
      setError(msg);
    } finally {
      setLoading(null);
    }
  }

  async function onDiscoverTenants() {
    if (!email) return;
    try {
      setError(null);
      const client = getClient();
      const res = await client.discoverTenants({ email });
      const list = Array.isArray((res as any)?.data?.tenants) ? (res as any).data.tenants : [];
      setTenants(list);
      if (list.length === 1) {
        setTenantId(list[0].id);
        setNeedsTenant(false);
      } else if (list.length > 1) {
        setNeedsTenant(true);
      }
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  }

  async function handleMfaVerify(e?: any) {
    if (e?.preventDefault) e.preventDefault();
    if (!mfa?.challenge_token || !mfaCode) return;
    setError(null);
    setLoading("password");
    try {
      const client = getClient();
      // eslint-disable-next-line no-console
      console.log('LOGIN mfaVerify -> sending', { challenge_token: mfa.challenge_token, code: mfaCode });
      const vr = await client.mfaVerify({ challenge_token: mfa.challenge_token, code: mfaCode, method: 'totp' });
      if (vr.meta.status === 200) {
        // eslint-disable-next-line no-console
        console.log('LOGIN mfaVerify -> success, fetching profile');
        const meRes = await client.me();
        // eslint-disable-next-line no-console
        console.log('LOGIN me() response', meRes.meta.status, meRes.data);
        if (meRes.meta.status === 200) setMe(meRes.data as any);
        setMfa(null);
      } else {
        setError("MFA verification failed");
      }
    } catch (e: any) {
      // eslint-disable-next-line no-console
      console.error('LOGIN mfaVerify error', e);
      setError(e?.message || String(e));
    } finally {
      setLoading(null);
    }
  }

  async function startSso(provider: "dev" | "workos") {
    setError(null);
    setLoading(provider === "dev" ? "sso-dev" : "sso-workos");
    try {
      const client = getClient();
      // Redirect back to dedicated callback handler with provider (and optional email) for the UI to complete token exchange
      const origin = window.location.origin;
      const qp = new URLSearchParams();
      qp.set("provider", provider);
      if (email) qp.set("email", email);
      const redirect = `${origin}/auth/callback?${qp.toString()}`;
      const res = await client.startSso(provider as any, { tenant_id: tenantId || undefined, redirect_url: redirect });
      const url = res.data?.redirect_url;
      if (url) window.location.href = url;
    } catch (err: any) {
      setError(err?.message || String(err));
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="w-full max-w-lg space-y-4 rounded-xl border p-6">
      <h2 className="text-lg font-semibold">Login</h2>
      {me ? (
        <div className="rounded-md border p-3 text-sm">
          <div className="font-medium">Logged in</div>
          <div>Email: {(me as any)?.email}</div>
          <div>Name: {(me as any)?.first_name} {(me as any)?.last_name}</div>
        </div>
      ) : (
        <form onSubmit={handlePasswordLogin} className="space-y-3">
          <div className="space-y-1">
            <label className="block text-sm font-medium">Email</label>
            <input
              data-testid="login-email"
              type="email"
              required
              className="w-full rounded-md border px-3 py-2 text-sm"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <div>
              <Button
                data-testid="login-discover"
                type="button"
                variant="secondary"
                disabled={!email || loading !== null}
                onClick={() => onDiscoverTenants()}
              >
                Find tenants
              </Button>
            </div>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium">Password</label>
            <input
              data-testid="login-password"
              type="password"
              required
              className="w-full rounded-md border px-3 py-2 text-sm"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <label className="block text-sm font-medium">Tenant ID (optional)</label>
              {needsTenant && <span className="text-xs text-amber-600">required for this account</span>}
            </div>
            <input
              data-testid="login-tenant"
              type="text"
              placeholder="tenant_123"
              className="w-full rounded-md border px-3 py-2 text-sm"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
            />
            {tenants.length > 1 && (
              <div className="mt-2">
                <label className="block text-sm font-medium">Select tenant</label>
                <select
                  data-testid="tenant-select"
                  className="w-full rounded-md border px-3 py-2 text-sm"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                >
                  <option value="">-- choose --</option>
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>{t.name ? `${t.name} (${t.id})` : t.id}</option>
                  ))}
                </select>
              </div>
            )}
          </div>
          {error && (
            <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-700" data-testid="login-error">
              {error}
            </div>
          )}
          {mfa && (
            <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 space-y-2" data-testid="login-mfa">
              <div className="font-medium">MFA challenge issued</div>
              <div className="text-xs text-amber-700">Enter the code from your authenticator app or SMS.</div>
              <div className="flex items-center gap-2">
                <input
                  data-testid="mfa-code"
                  type="text"
                  placeholder="123456"
                  className="w-40 rounded-md border px-3 py-2 text-sm"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleMfaVerify(); }}
                />
                <Button data-testid="mfa-verify" type="button" disabled={loading !== null || !mfaCode.trim()} onClick={() => handleMfaVerify()}>
                  Verify
                </Button>
              </div>
            </div>
          )}
          <div className="flex gap-2">
            <Button data-testid="login-submit" type="submit" disabled={loading !== null}>
              {loading === "password" ? "Signing in..." : "Sign in"}
            </Button>
          </div>
        </form>
      )}

      {!me && (
        <div className="space-y-2 pt-2">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">or</div>
          <div className="flex flex-wrap gap-2">
            <Button
              data-testid="login-sso-dev"
              variant="secondary"
              disabled={loading !== null}
              onClick={() => startSso("dev")}
            >
              {loading === "sso-dev" ? "Starting Dev SSO..." : "Continue with Dev SSO"}
            </Button>
            <Button
              data-testid="login-sso-workos"
              variant="secondary"
              disabled={loading !== null}
              onClick={() => startSso("workos")}
            >
              {loading === "sso-workos" ? "Starting WorkOS SSO..." : "Continue with WorkOS SSO"}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
