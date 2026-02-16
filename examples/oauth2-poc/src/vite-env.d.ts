/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GUARD_BASE_URL?: string
  readonly VITE_OAUTH_CLIENT_ID?: string
  readonly VITE_REDIRECT_URI?: string
  readonly VITE_OAUTH_SCOPE?: string
  readonly VITE_TENANT_ID?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
