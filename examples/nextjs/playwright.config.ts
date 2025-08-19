import { defineConfig, devices } from '@playwright/test';
import * as path from 'path';
import * as dotenv from 'dotenv';

// Load repo root .env.conformance for seeded test credentials if present
// Use process.cwd() to avoid __dirname in ESM
dotenv.config({ path: path.resolve(process.cwd(), '../../.env.conformance') });

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  use: {
    baseURL: 'http://localhost:3001',
    trace: 'retain-on-failure',
  },
  reporter: 'list',
  webServer: {
    command: 'npm run dev',
    port: 3001,
    reuseExistingServer: false,
    env: {
      PORT: '3001',
      ENABLE_TEST_ROUTES: 'true',
      NEXT_TELEMETRY_DISABLE: '1',
      // GUARD_BASE_URL and GUARD_TENANT_ID are read by Next from .env.local
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
