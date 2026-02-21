import { describe, expect, it } from 'vitest';
import { noopStorage } from './tokens';

describe('noopStorage', () => {
  it('returns null for both tokens and ignores writes', async () => {
    expect(await noopStorage.getAccessToken()).toBeNull();
    expect(await noopStorage.getRefreshToken()).toBeNull();

    await noopStorage.setAccessToken('a');
    await noopStorage.setRefreshToken('r');

    expect(await noopStorage.getAccessToken()).toBeNull();
    expect(await noopStorage.getRefreshToken()).toBeNull();

    await noopStorage.clear();
    expect(await noopStorage.getAccessToken()).toBeNull();
  });
});
