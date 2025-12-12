import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 1,
  duration: '30s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
  },
};

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';
const TENANT_ID = __ENV.K6_TENANT_ID || '';
const ORG_ID = __ENV.K6_ORG_ID || '';
const ADMIN_TOKEN = __ENV.K6_ADMIN_TOKEN || '';
const INTENT = __ENV.K6_INTENT || 'sso';

if (!TENANT_ID) {
  console.error('K6_TENANT_ID is required');
}
if (!ORG_ID) {
  console.error('K6_ORG_ID is required');
}
if (!ADMIN_TOKEN) {
  console.error('K6_ADMIN_TOKEN is required');
}

export default function () {
  if (!TENANT_ID || !ORG_ID || !ADMIN_TOKEN) {
    sleep(1);
    return;
  }
  const url = `${BASE_URL}/api/v1/auth/sso/workos/portal-link?tenant_id=${encodeURIComponent(TENANT_ID)}&organization_id=${encodeURIComponent(ORG_ID)}&intent=${encodeURIComponent(INTENT)}`;
  const res = http.get(url, {
    headers: {
      Authorization: `Bearer ${ADMIN_TOKEN}`,
      Accept: 'application/json',
    },
    timeout: '10s',
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has link field': (r) => {
      try {
        const body = JSON.parse(r.body);
        return typeof body.link === 'string' && body.link.length > 0;
      } catch (e) {
        return false;
      }
    },
  });

  sleep(1);
}
