import type { OAuthPending, OAuthSession, POCConfig } from './types'

const CONFIG_KEY = 'guard_oauth2_poc_config'
const PENDING_KEY = 'guard_oauth2_poc_pending'
const SESSION_KEY = 'guard_oauth2_poc_session'

export function loadConfig(): POCConfig | null {
  try {
    const raw = localStorage.getItem(CONFIG_KEY)
    if (!raw) return null
    return JSON.parse(raw) as POCConfig
  } catch {
    return null
  }
}

export function saveConfig(config: POCConfig): void {
  localStorage.setItem(CONFIG_KEY, JSON.stringify(config))
}

export function loadPending(): OAuthPending | null {
  try {
    const raw = localStorage.getItem(PENDING_KEY)
    if (!raw) return null
    return JSON.parse(raw) as OAuthPending
  } catch {
    return null
  }
}

export function savePending(pending: OAuthPending): void {
  localStorage.setItem(PENDING_KEY, JSON.stringify(pending))
}

export function clearPending(): void {
  localStorage.removeItem(PENDING_KEY)
}

export function loadSession(): OAuthSession | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    if (!raw) return null
    return JSON.parse(raw) as OAuthSession
  } catch {
    return null
  }
}

export function saveSession(session: OAuthSession): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session))
}

export function clearSession(): void {
  localStorage.removeItem(SESSION_KEY)
}
