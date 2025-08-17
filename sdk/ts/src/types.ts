export type HeadersMap = Record<string, string>;

export interface Meta {
  status: number;
  requestId?: string;
  headers?: HeadersMap;
}

export interface ResponseWrapper<T> {
  data: T;
  meta: Meta;
}

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type TenantId = string;

export type SsoProvider =
  | 'workos'
  | 'dev'
  // placeholders for future socials
  | 'google'
  | 'github'
  | 'apple';
