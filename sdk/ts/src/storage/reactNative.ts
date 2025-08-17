import type { TokenStorage } from '../tokens';

const ACCESS_KEY = 'guard_access_token';
const REFRESH_KEY = 'guard_refresh_token';

export interface AsyncStorageLike {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export function reactNativeStorageAdapter(AsyncStorage: AsyncStorageLike, prefix = ''): TokenStorage {
  const p = prefix ? `${prefix}:` : '';
  const k = (key: string) => `${p}${key}`;

  return {
    async getAccessToken() {
      return AsyncStorage.getItem(k(ACCESS_KEY));
    },
    async setAccessToken(token: string | null) {
      if (token == null) return AsyncStorage.removeItem(k(ACCESS_KEY));
      return AsyncStorage.setItem(k(ACCESS_KEY), token);
    },
    async getRefreshToken() {
      return AsyncStorage.getItem(k(REFRESH_KEY));
    },
    async setRefreshToken(token: string | null) {
      if (token == null) return AsyncStorage.removeItem(k(REFRESH_KEY));
      return AsyncStorage.setItem(k(REFRESH_KEY), token);
    },
    async clear() {
      await AsyncStorage.removeItem(k(ACCESS_KEY));
      await AsyncStorage.removeItem(k(REFRESH_KEY));
    },
  };
}
