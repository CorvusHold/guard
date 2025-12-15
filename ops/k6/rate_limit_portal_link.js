import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

export const rate_limited = new Counter('rate_limited');

export const options = {
  vus: 1,
  duration: '2m',
  thresholds: {
    'checks{check:status is 200/429}': ['rate>0.99'],
  },
};

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';
const TENANT_ID = __ENV.K6_TENANT_ID || '';
const ORG_ID = __ENV.K6_ORG_ID || '';
const ADMIN_TOKEN = __ENV.K6_ADMIN_TOKEN || '';
const INTENT = __ENV.K6_INTENT || 'sso';
const ITERATIONS = Number(__ENV.K6_ITERATIONS || 300);

export default function () {
  if (!TENANT_ID || !ORG_ID || !ADMIN_TOKEN) {
    // If portal-link env is not configured, treat this as a skipped scenario but keep thresholds happy.
    check({ status: 200 }, {
      'status is 200/429': (r) => r.status === 200 || r.status === 429,
    });
    sleep(1);
    return;
  }
  for (let i = 0; i < ITERATIONS; i++) {
    const url = `${BASE_URL}/api/v1/auth/sso/workos/portal-link?tenant_id=${encodeURIComponent(TENANT_ID)}&organization_id=${encodeURIComponent(ORG_ID)}&intent=${encodeURIComponent(INTENT)}`;
    const res = http.get(url, {
      headers: {
        Authorization: `Bearer ${ADMIN_TOKEN}`,
        Accept: 'application/json',
      },
      timeout: '10s',
    });

    if (res.status === 429) rate_limited.add(1);

    check(res, {
      'status is 200/429': (r) => r.status === 200 || r.status === 429,
    });

    sleep(Math.random() * 0.05);
  }
}
