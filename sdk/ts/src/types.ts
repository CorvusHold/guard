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

/**
 * SSO provider slug - can be any string configured in the tenant's SSO providers.
 * Common values include 'okta', 'azure-ad', 'google-saml', 'onelogin', etc.
 * Legacy values 'workos' and 'dev' are still supported for backward compatibility.
 */
export type SsoProviderSlug = string;

/**
 * @deprecated Use SsoProviderSlug instead. This type is kept for backward compatibility.
 */
export type SsoProvider = SsoProviderSlug;
