"use client";

import { useEffect, useState } from "react";

type MeResponse = {
  data?: any;
  meta: { status: number };
  error?: any;
};

export default function Page() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Signup form state
  const [signupEmail, setSignupEmail] = useState("");
  const [signupPassword, setSignupPassword] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [profile, setProfile] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [profileLoading, setProfileLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Magic Link UI state
  const [magicEmail, setMagicEmail] = useState("");
  const [magicToken, setMagicToken] = useState("");
  const [info, setInfo] = useState<string | null>(null);

  async function fetchMe() {
    setProfileLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/me", { cache: "no-store" });
      const j: MeResponse = await r.json();
      if (r.ok) setProfile(j.data);
      else setError(j.error || `Me failed: ${j.meta?.status}`);
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setProfileLoading(false);
    }
  }

  async function onMagicSend(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setInfo(null);
    try {
      const redirect_url = typeof window !== 'undefined' ? `${window.location.origin}/magic/complete` : undefined;
      const r = await fetch('/api/magic/send', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: magicEmail, redirect_url }),
      });
      if (r.ok) {
        setInfo('Magic link sent (check server logs or configured email provider).');
      } else {
        const j = await r.json();
        setError(j.error || `Magic send failed: ${r.status}`);
      }
    } catch (e: any) {
      setError(e?.message || 'failed');
    } finally {
      setLoading(false);
    }
  }

  async function onMagicVerify(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setInfo(null);
    try {
      const r = await fetch(`/api/magic/verify?token=${encodeURIComponent(magicToken)}`, { credentials: 'include' });
      if (r.ok) {
        setMagicToken('');
        await new Promise((r) => setTimeout(r, 300));
        await fetchMe();
        setInfo('Magic verified!');
      } else {
        const j = await r.json();
        setError(j.error || `Magic verify failed: ${r.status}`);
      }
    } catch (e: any) {
      setError(e?.message || 'failed');
    } finally {
      setLoading(false);
    }
  }

  function onStartSSOWorkOS() {
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    const u = `/api/sso/workos/start?redirect_url=${encodeURIComponent(origin)}`;
    window.location.href = u;
  }

  useEffect(() => {
    // Try to load profile on mount if cookies exist
    fetchMe();
  }, []);

  async function onLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setChallengeToken(null);
    try {
      const r = await fetch("/api/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (r.status === 200) {
        // cookies set; fetch profile
        await fetchMe();
      } else if (r.status === 202) {
        const j = await r.json();
        setChallengeToken(j.challenge_token);
      } else {
        const j = await r.json();
        setError(j.error || `Login failed: ${r.status}`);
      }
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setLoading(false);
    }
  }

  async function onSignup(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setInfo(null);
    try {
      const r = await fetch("/api/signup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: 'include',
        body: JSON.stringify({ email: signupEmail, password: signupPassword, first_name: firstName, last_name: lastName }),
      });
      if (r.ok) {
        setSignupEmail("");
        setSignupPassword("");
        setFirstName("");
        setLastName("");
        // Give the browser a moment to apply Set-Cookie then fetch profile once (server route retries internally)
        await new Promise((r) => setTimeout(r, 300));
        await fetchMe();
        setInfo("Registration successful.");
      } else {
        const j = await r.json();
        setError(j.error || `Signup failed: ${r.status}`);
      }
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setLoading(false);
    }
  }

  async function onVerifyMFA(e: React.FormEvent) {
    e.preventDefault();
    if (!challengeToken) return;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/mfa/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ challenge_token: challengeToken, method: "totp", code: mfaCode }),
      });
      if (r.ok) {
        setChallengeToken(null);
        setMfaCode("");
        await fetchMe();
      } else {
        const j = await r.json();
        setError(j.error || `Verify failed: ${r.status}`);
      }
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setLoading(false);
    }
  }

  async function onRefresh() {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch("/api/refresh", { method: "POST" });
      if (!r.ok) {
        const j = await r.json();
        setError(j.error || `Refresh failed: ${r.status}`);
      }
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

  return (
    <div className="card" data-testid="home">
      {profile ? (
        <div>
          <h2>Welcome</h2>
          <pre style={{ whiteSpace: "pre-wrap" }} data-testid="profile-json">{JSON.stringify(profile, null, 2)}</pre>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={fetchMe} disabled={profileLoading} data-testid="btn-refresh-profile">Refresh Profile</button>
            <button onClick={onRefresh} disabled={loading} data-testid="btn-refresh-tokens">Refresh Tokens</button>
            <button onClick={onLogout} disabled={loading} data-testid="btn-logout">Logout</button>
            <a href="/protected" data-testid="link-protected">Go to Protected</a>
            {Array.isArray(profile?.roles) && profile.roles.includes('owner') && (
              <a href="/settings" data-testid="link-settings">Settings</a>
            )}
          </div>
        </div>
      ) : challengeToken ? (
        <form onSubmit={onVerifyMFA}>
          <h2>MFA Verification</h2>
          <p style={{ wordBreak: "break-all" }}>Challenge: {challengeToken}</p>
          <label htmlFor="code">TOTP Code</label>
          <input id="code" value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="123456" data-testid="input-mfa-code" />
          <div style={{ marginTop: 12 }}>
            <button type="submit" disabled={loading} data-testid="btn-verify-mfa">Verify</button>
          </div>
        </form>
      ) : (
        <div style={{ display: 'grid', gap: 24 }}>
          <form onSubmit={onLogin}>
            <h2>Login</h2>
            <label htmlFor="email">Email</label>
            <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="user@example.com" data-testid="input-email" />
            <label htmlFor="password">Password</label>
            <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" data-testid="input-password" />
            <div style={{ marginTop: 12 }}>
              <button type="submit" disabled={loading} data-testid="btn-login">Login</button>
            </div>
          </form>

          <form onSubmit={onSignup}>
            <h2>Register</h2>
            <label htmlFor="signupEmail">Email</label>
            <input id="signupEmail" type="email" value={signupEmail} onChange={(e) => setSignupEmail(e.target.value)} placeholder="newuser@example.com" data-testid="input-signup-email" />
            <label htmlFor="signupPassword">Password</label>
            <input id="signupPassword" type="password" value={signupPassword} onChange={(e) => setSignupPassword(e.target.value)} placeholder="••••••••" data-testid="input-signup-password" />
            <label htmlFor="firstName">First Name</label>
            <input id="firstName" value={firstName} onChange={(e) => setFirstName(e.target.value)} placeholder="Jane" data-testid="input-first-name" />
            <label htmlFor="lastName">Last Name</label>
            <input id="lastName" value={lastName} onChange={(e) => setLastName(e.target.value)} placeholder="Doe" data-testid="input-last-name" />
            <div style={{ marginTop: 12 }}>
              <button type="submit" disabled={loading} data-testid="btn-signup">Create Account</button>
            </div>
          </form>

          <div>
            <h2>Magic Link</h2>
            <form onSubmit={onMagicSend}>
              <label htmlFor="magicEmail">Email</label>
              <input id="magicEmail" type="email" value={magicEmail} onChange={(e) => setMagicEmail(e.target.value)} placeholder="user@example.com" data-testid="input-magic-email" />
              <div style={{ marginTop: 12 }}>
                <button type="submit" disabled={loading} data-testid="btn-magic-send">Send Magic Link</button>
                <a style={{ marginLeft: 8 }} href="/magic/complete" title="Open magic completion page" data-testid="link-magic-complete">Open Magic Complete Page</a>
              </div>
            </form>

            <form onSubmit={onMagicVerify} style={{ marginTop: 12 }}>
              <label htmlFor="magicToken">Paste Token (dev/testing)</label>
              <input id="magicToken" value={magicToken} onChange={(e) => setMagicToken(e.target.value)} placeholder="eyJhbGciOi..." data-testid="input-magic-token" />
              <div style={{ marginTop: 12 }}>
                <button type="submit" disabled={loading} data-testid="btn-magic-verify">Verify Token</button>
              </div>
            </form>
          </div>

          <div>
            <h2>SSO (WorkOS)</h2>
            <button onClick={onStartSSOWorkOS} disabled={loading} data-testid="btn-sso-workos">Continue with WorkOS</button>
          </div>
        </div>
      )}

      {info && <p style={{ color: "#065f46", marginTop: 12 }} data-testid="info">{info}</p>}
      {error && (<p style={{ color: "#b91c1c", marginTop: 12 }} data-testid="error">Error: {error}</p>)}
    </div>
  );
}
