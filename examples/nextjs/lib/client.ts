import { GuardClient } from '@corvushold/guard-sdk';
import { createCookieStorage } from './storage';
import type { NextRequest } from 'next/server';

export function getClient() {
  const baseUrl = process.env.GUARD_BASE_URL;
  if (!baseUrl) throw new Error('GUARD_BASE_URL is not set');
  const tenantId = process.env.GUARD_TENANT_ID;
  return new GuardClient({ baseUrl, tenantId });
}

export function getClientFromCookies(req: NextRequest) {
  const baseUrl = process.env.GUARD_BASE_URL;
  if (!baseUrl) throw new Error('GUARD_BASE_URL is not set');
  const tenantId = process.env.GUARD_TENANT_ID;
  const access = req.cookies.get('guard_access_token')?.value ?? null;
  const refresh = req.cookies.get('guard_refresh_token')?.value ?? null;
  const storage = createCookieStorage(access, refresh);
  return new GuardClient({ baseUrl, tenantId, storage });
}
