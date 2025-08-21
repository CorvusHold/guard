import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const method = req.method;
  const purpose = req.headers.get('purpose') || req.headers.get('sec-purpose');
  const mwPrefetch = req.headers.get('x-middleware-prefetch');
  const isPrefetch = !!(purpose && purpose.toLowerCase().includes('prefetch'));
  const isMWPrefetch = mwPrefetch === '1';

  // Skip Next internal and static assets defensively
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon') ||
    pathname.startsWith('/icons') ||
    pathname.startsWith('/static')
  ) {
    return NextResponse.next();
  }

  // Let prefetch/HEAD pass through to avoid noisy redirects during link hovering
  if (method === 'HEAD' || isPrefetch || isMWPrefetch) {
    return NextResponse.next();
  }
  // Protect /protected/* routes: require access token cookie
  if (
    pathname.startsWith('/protected') ||
    pathname.startsWith('/settings') ||
    pathname.startsWith('/admin') ||
    pathname.startsWith('/sessions')
  ) {
    const hasAccess = req.cookies.get('guard_access_token');
    if (!hasAccess) {
      const url = new URL('/', req.url);
      return NextResponse.redirect(url);
    }
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/protected/:path*',
    '/settings/:path*',
    '/settings',
    '/admin/:path*',
    '/admin',
    '/sessions/:path*',
    '/sessions',
  ],
};
