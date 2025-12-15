import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 20 },   // ramp to 20 VUs
    { duration: '2m', target: 50 },    // ramp to 50 VUs
    { duration: '3m', target: 50 },    // hold
    { duration: '30s', target: 0 },    // ramp down
  ],
  thresholds: {
    'checks{check:status is 200/202/429}': ['rate>0.99'], // <1% errors
    http_req_duration: ['p(95)<500'], // p95 < 500ms
  },
};

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';
const TENANT_ID = __ENV.K6_TENANT_ID || '';
const EMAIL = __ENV.K6_EMAIL || '';
const PASSWORD = __ENV.K6_PASSWORD || '';

export default function () {
  const payload = JSON.stringify({
    tenant_id: TENANT_ID,
    email: EMAIL,
    password: PASSWORD,
  });

  const res = http.post(`${BASE_URL}/api/v1/auth/password/login`, payload, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
  });

  // Accept 200 OK or 202 Accepted (MFA challenge); if 202, consider as success for throughput.
  check(res, {
    'status is 200/202/429': (r) => r.status === 200 || r.status === 202 || r.status === 429,
  });

  // small randomized sleep to avoid lockstep
  sleep(Math.random() * 0.5);
}
