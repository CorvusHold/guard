import { describe, expect, it } from 'vitest';
import { InMemoryStorage } from './inMemory';
import { WebLocalStorage } from './webLocalStorage';
import { reactNativeStorageAdapter, type AsyncStorageLike } from './reactNative';

describe('storage adapters', () => {
  it('InMemoryStorage stores and clears access/refresh tokens', () => {
    const s = new InMemoryStorage();

    expect(s.getAccessToken()).toBeNull();
    expect(s.getRefreshToken()).toBeNull();

    s.setAccessToken('a');
    s.setRefreshToken('r');

    expect(s.getAccessToken()).toBe('a');
    expect(s.getRefreshToken()).toBe('r');

    s.clear();

    expect(s.getAccessToken()).toBeNull();
    expect(s.getRefreshToken()).toBeNull();
  });

  it('WebLocalStorage is a no-op outside browser contexts', () => {
    const previousWindow = (globalThis as any).window;
    // Simulate non-browser runtime
    delete (globalThis as any).window;

    const s = new WebLocalStorage('app');

    expect(s.getAccessToken()).toBeNull();
    expect(s.getRefreshToken()).toBeNull();
    s.setAccessToken('a');
    s.setRefreshToken('r');
    s.clear();

    (globalThis as any).window = previousWindow;
  });

  it('WebLocalStorage persists with optional prefix', () => {
    const previousWindow = (globalThis as any).window;
    const mem = new Map<string, string>();
    const localStorage = {
      getItem: (k: string) => (mem.has(k) ? mem.get(k)! : null),
      setItem: (k: string, v: string) => {
        mem.set(k, v);
      },
      removeItem: (k: string) => {
        mem.delete(k);
      },
    };

    (globalThis as any).window = { localStorage };
    const s = new WebLocalStorage('myapp');

    s.setAccessToken('access-token');
    s.setRefreshToken('refresh-token');

    expect(mem.get('myapp:guard_access_token')).toBe('access-token');
    expect(mem.get('myapp:guard_refresh_token')).toBe('refresh-token');
    expect(s.getAccessToken()).toBe('access-token');
    expect(s.getRefreshToken()).toBe('refresh-token');

    s.setAccessToken(null);
    s.setRefreshToken(null);

    expect(mem.has('myapp:guard_access_token')).toBe(false);
    expect(mem.has('myapp:guard_refresh_token')).toBe(false);

    (globalThis as any).window = previousWindow;
  });

  it('reactNativeStorageAdapter reads/writes with prefix and clear', async () => {
    const mem = new Map<string, string>();
    const asyncStorage: AsyncStorageLike = {
      async getItem(key) {
        return mem.has(key) ? mem.get(key)! : null;
      },
      async setItem(key, value) {
        mem.set(key, value);
      },
      async removeItem(key) {
        mem.delete(key);
      },
    };

    const s = reactNativeStorageAdapter(asyncStorage, 'rn');

    await s.setAccessToken('a');
    await s.setRefreshToken('r');

    expect(await s.getAccessToken()).toBe('a');
    expect(await s.getRefreshToken()).toBe('r');

    expect(mem.get('rn:guard_access_token')).toBe('a');
    expect(mem.get('rn:guard_refresh_token')).toBe('r');

    await s.clear();

    expect(await s.getAccessToken()).toBeNull();
    expect(await s.getRefreshToken()).toBeNull();
  });
});
