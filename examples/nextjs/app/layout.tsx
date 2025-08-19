import './globals.css';
import type { ReactNode } from 'react';

export const metadata = {
  title: 'Guard Next.js Example',
  description: 'Password + MFA example using @corvushold/guard-sdk',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <main style={{ maxWidth: 480, margin: '40px auto', fontFamily: 'system-ui, sans-serif' }}>
          <h1>Guard Next.js Example</h1>
          {children}
        </main>
      </body>
    </html>
  );
}
