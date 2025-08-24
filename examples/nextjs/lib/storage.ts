import type { TokenStorage } from '@corvushold/guard-sdk';

export function createCookieStorage(access?: string | null, refresh?: string | null): TokenStorage {
  return {
    getAccessToken: () => access ?? null,
    setAccessToken: () => {},
    getRefreshToken: () => refresh ?? null,
    setRefreshToken: () => {},
    clear: () => {},
  };
}
