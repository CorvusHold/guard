import type { TokenStorage } from '../tokens';

const ACCESS_KEY = 'guard_access_token';
const REFRESH_KEY = 'guard_refresh_token';

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
}

export class WebLocalStorage implements TokenStorage {
  private readonly prefix: string;

  constructor(prefix = '') {
    this.prefix = prefix ? `${prefix}:` : '';
  }

  private k(key: string): string {
    return `${this.prefix}${key}`;
  }

  getAccessToken(): string | null {
    if (!isBrowser()) return null;
    return window.localStorage.getItem(this.k(ACCESS_KEY));
  }

  setAccessToken(token: string | null): void {
    if (!isBrowser()) return;
    if (token == null) window.localStorage.removeItem(this.k(ACCESS_KEY));
    else window.localStorage.setItem(this.k(ACCESS_KEY), token);
  }

  getRefreshToken(): string | null {
    if (!isBrowser()) return null;
    return window.localStorage.getItem(this.k(REFRESH_KEY));
  }

  setRefreshToken(token: string | null): void {
    if (!isBrowser()) return;
    if (token == null) window.localStorage.removeItem(this.k(REFRESH_KEY));
    else window.localStorage.setItem(this.k(REFRESH_KEY), token);
  }

  clear(): void {
    if (!isBrowser()) return;
    window.localStorage.removeItem(this.k(ACCESS_KEY));
    window.localStorage.removeItem(this.k(REFRESH_KEY));
  }
}
