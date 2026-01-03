import { GuardClient } from '../../../sdk/ts/src/client'
import { WebLocalStorage } from '../../../sdk/ts/src/storage/webLocalStorage'
import { getRuntimeConfig } from './runtime'

// Re-export types for use in components
export type {
  SsoProviderItem,
  SsoProviderType,
  SsoLinkingPolicy,
  SsoProvidersListResp,
  CreateSsoProviderReq,
  UpdateSsoProviderReq,
  SsoTestProviderResp,
  SsoSPInfoResp,
  SsoProviderOption,
  LoginOptionsResp
} from '../../../sdk/ts/src/client'

let client: GuardClient | null = null
let lastBaseUrl: string | null = null
let lastAuthMode: 'bearer' | 'cookie' | null = null

function getCookie(name: string): string | null {
  try {
    return document.cookie
      .split(';')
      .map((c) => c.trim())
      .find((c) => c.startsWith(`${name}=`))
      ?.split('=')[1] || null
  } catch (_) {
    return null
  }
}

export function getClient(): GuardClient {
  const cfg = getRuntimeConfig()
  if (!cfg) throw new Error('Guard base URL is not configured')
  if (
    client &&
    lastBaseUrl === cfg.guard_base_url &&
    lastAuthMode === cfg.auth_mode
  )
    return client
  if (cfg.auth_mode === 'cookie') {
    const bearerFromCookie = getCookie('guard_access_token')
    const defaultHeaders =
      bearerFromCookie != null
        ? { Authorization: `Bearer ${bearerFromCookie}` }
        : undefined
    client = new GuardClient({
      baseUrl: cfg.guard_base_url,
      authMode: 'cookie',
      defaultHeaders
    })
  } else {
    // bearer with persistent storage
    const storage = new WebLocalStorage('guard_ui')
    client = new GuardClient({
      baseUrl: cfg.guard_base_url,
      authMode: 'bearer',
      storage
    })
  }
  lastBaseUrl = cfg.guard_base_url
  lastAuthMode = cfg.auth_mode
  return client
}
