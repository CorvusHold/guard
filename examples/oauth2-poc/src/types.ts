export interface POCConfig {
  guardBaseUrl: string
  clientId: string
  redirectUri: string
  scope: string
  tenantId: string
}

export interface OAuthPending {
  state: string
  nonce: string
  codeVerifier: string
  createdAt: number
}

export interface OAuthSession {
  accessToken: string
  refreshToken?: string
  idToken?: string
  tokenType?: string
  expiresIn?: number
  scope?: string
  createdAt: number
}

export interface UserInfo {
  id: string
  email: string
  first_name?: string
  last_name?: string
  roles?: string[]
}
