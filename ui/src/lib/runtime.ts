export type RuntimeConfig = {
  guard_base_url: string;
  source: string; // "redirect" | "direct" | other
};

const RUNTIME_KEY = "guard_runtime";

export function getRuntimeConfig(): RuntimeConfig | null {
  try {
    const raw = localStorage.getItem(RUNTIME_KEY);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (typeof obj?.guard_base_url === "string" && obj.guard_base_url.length > 0) {
      return { guard_base_url: obj.guard_base_url, source: String(obj.source || "") };
    }
  } catch (_) {
    // ignore
  }
  return null;
}

export function setRuntimeConfig(cfg: RuntimeConfig): void {
  // lightweight validation
  try {
    // throws if invalid URL
    // Allow relative? For our use-case we expect absolute HTTP(S)
    const u = new URL(cfg.guard_base_url);
    if (!/^https?:$/.test(u.protocol)) throw new Error("invalid protocol");
  } catch (e) {
    throw new Error("Invalid guard_base_url");
  }
  localStorage.setItem(RUNTIME_KEY, JSON.stringify(cfg));
}

export function clearRuntimeConfig(): void {
  localStorage.removeItem(RUNTIME_KEY);
}

export function ensureRuntimeConfigFromQuery(): void {
  const usp = new URLSearchParams(window.location.search);
  const base = usp.get("guard-base-url");
  if (!base) return;
  const source = usp.get("source") || "redirect";
  try {
    setRuntimeConfig({ guard_base_url: base, source });
  } catch (_) {
    // invalid url -> ignore persistence
  }
  // Clean the URL to remove secrets/params
  try {
    const { pathname, hash } = window.location;
    const newUrl = pathname + (hash || "");
    window.history.replaceState({}, "", newUrl);
  } catch (_) {
    // ignore
  }
}
