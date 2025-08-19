import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  // Protect /protected/* routes: require access token cookie
  if (pathname.startsWith('/protected') || pathname.startsWith('/settings')) {
    const hasAccess = req.cookies.get('guard_access_token');
    if (!hasAccess) {
      const url = new URL('/', req.url);
      return NextResponse.redirect(url);
    }
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/protected/:path*', '/settings/:path*', '/settings'],
};
