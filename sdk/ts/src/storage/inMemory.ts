import type { TokenStorage } from '../tokens';

export class InMemoryStorage implements TokenStorage {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  getAccessToken(): string | null {
    return this.accessToken;
  }
  setAccessToken(token: string | null): void {
    this.accessToken = token ?? null;
  }
  getRefreshToken(): string | null {
    return this.refreshToken;
  }
  setRefreshToken(token: string | null): void {
    this.refreshToken = token ?? null;
  }
  clear(): void {
    this.accessToken = null;
    this.refreshToken = null;
  }
}
