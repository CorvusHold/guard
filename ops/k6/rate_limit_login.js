import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

export const rate_limited = new Counter('rate_limited');

export const options = {
  vus: 1,
  duration: '2m',
  thresholds: {
    // Ensure we actually hit rate limiting at least once
    rate_limited: ['count>0'],
    // Accept 200/202/429 as success for this scenario
    'checks{check:status is 200/202/429}': ['rate>0.99'],
  },
};

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';
const TENANT_ID = __ENV.K6_TENANT_ID || '';
const EMAIL = __ENV.K6_EMAIL || '';
const PASSWORD = __ENV.K6_PASSWORD || '';
const ITERATIONS = Number(__ENV.K6_ITERATIONS || 200);

export default function () {
  for (let i = 0; i < ITERATIONS; i++) {
    const payload = JSON.stringify({
      tenant_id: TENANT_ID,
      email: EMAIL,
      password: PASSWORD,
    });

    const res = http.post(`${BASE_URL}/api/v1/auth/password/login`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '10s',
    });

    if (res.status === 429) {
      rate_limited.add(1);
    }

    // Accept 200 OK, 202 Accepted (MFA challenge), and 429 Too Many Requests
    check(res, {
      'status is 200/202/429': (r) => r.status === 200 || r.status === 202 || r.status === 429,
    });

    // short jitter to avoid pure lockstep
    sleep(Math.random() * 0.05);
  }
}
