import { GuardClient } from '../../../sdk/ts/src/client'
import { WebLocalStorage } from '../../../sdk/ts/src/storage/webLocalStorage'
import { getRuntimeConfig } from './runtime'

// Re-export types for use in components
export type {
  SsoProviderItem,
  SsoProviderType,
  SsoProvidersListResp,
  CreateSsoProviderReq,
  UpdateSsoProviderReq,
  SsoTestProviderResp
} from '../../../sdk/ts/src/client'

let client: GuardClient | null = null
let lastBaseUrl: string | null = null
let lastAuthMode: 'bearer' | 'cookie' | null = null

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
    client = new GuardClient({
      baseUrl: cfg.guard_base_url,
      authMode: 'cookie'
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
