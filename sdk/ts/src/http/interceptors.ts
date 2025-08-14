import type { FetchLike } from '../types';

export type RequestInterceptor = (
  input: RequestInfo | URL,
  init: RequestInit
) => Promise<[RequestInfo | URL, RequestInit]> | [RequestInfo | URL, RequestInit];

export type ResponseInterceptor = (response: Response) => Promise<Response> | Response;

export interface Interceptors {
  request?: RequestInterceptor[];
  response?: ResponseInterceptor[];
}

export function applyRequestInterceptors(
  input: RequestInfo | URL,
  init: RequestInit,
  interceptors?: RequestInterceptor[]
): Promise<[RequestInfo | URL, RequestInit]> | [RequestInfo | URL, RequestInit] {
  if (!interceptors || interceptors.length === 0) return [input, init];
  let chain = Promise.resolve<[RequestInfo | URL, RequestInit]>([input, init]);
  for (const fn of interceptors) {
    chain = chain.then(([i, n]) => Promise.resolve(fn(i, n)));
  }
  return chain;
}

export async function applyResponseInterceptors(
  response: Response,
  interceptors?: ResponseInterceptor[]
): Promise<Response> {
  if (!interceptors || interceptors.length === 0) return response;
  let res = response;
  for (const fn of interceptors) {
    // Allow interceptor to clone/consume as needed
    // Always pass along the result for next interceptor
    // eslint-disable-next-line no-await-in-loop
    res = await Promise.resolve(fn(res));
  }
  return res;
}
