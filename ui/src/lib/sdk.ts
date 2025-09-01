import { GuardClient } from "../../../sdk/ts/src/client";
import { getRuntimeConfig } from "./runtime";

let client: GuardClient | null = null;
let lastBaseUrl: string | null = null;

export function getClient(): GuardClient {
  const cfg = getRuntimeConfig();
  if (!cfg) throw new Error("Guard base URL is not configured");
  if (client && lastBaseUrl === cfg.guard_base_url) return client;
  client = new GuardClient({ baseUrl: cfg.guard_base_url });
  lastBaseUrl = cfg.guard_base_url;
  return client;
}
