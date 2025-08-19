"use client";

import { useEffect, useState } from "react";

export default function MagicCompletePage() {
  const [status, setStatus] = useState<string>("Verifying magic link...");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const usp = new URLSearchParams(window.location.search);
    const token = usp.get("token");
    if (!token) {
      setError("Missing token");
      setStatus("Failed");
      return;
    }
    (async () => {
      try {
        const r = await fetch(`/api/magic/verify?token=${encodeURIComponent(token)}`);
        if (r.ok) {
          setStatus("Success! Redirecting...");
          setTimeout(() => { window.location.href = "/"; }, 800);
        } else {
          const j = await r.json().catch(() => ({}));
          setError(j?.error || `Verify failed: ${r.status}`);
          setStatus("Failed");
        }
      } catch (e: any) {
        setError(e?.message || "failed");
        setStatus("Failed");
      }
    })();
  }, []);

  return (
    <div className="card">
      <h2>Magic Link</h2>
      <p>{status}</p>
      {error && <p style={{ color: "#b91c1c" }}>Error: {error}</p>}
      <a href="/">Back to Home</a>
    </div>
  );
}
