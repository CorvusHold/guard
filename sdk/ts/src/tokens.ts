export interface TokenStorage {
  getAccessToken(): Promise<string | null> | string | null;
  setAccessToken(token: string | null): Promise<void> | void;
  getRefreshToken(): Promise<string | null> | string | null;
  setRefreshToken(token: string | null): Promise<void> | void;
  clear(): Promise<void> | void;
}

export interface TokenProvider {
  getAccessToken(): Promise<string | null> | string | null;
}

export const noopStorage: TokenStorage = {
  getAccessToken: () => null,
  setAccessToken: () => {},
  getRefreshToken: () => null,
  setRefreshToken: () => {},
  clear: () => {},
};
