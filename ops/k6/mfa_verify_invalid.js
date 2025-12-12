import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 10,
  duration: '1m',
  thresholds: {
    'checks{check:got 400/401/429}': ['rate>0.95'],
  },
};

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';

export default function () {
  const payload = JSON.stringify({
    challenge_token: 'invalid.challenge.token',
    method: 'totp',
    code: '000000',
  });

  const res = http.post(`${BASE_URL}/api/v1/auth/mfa/verify`, payload, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '5s',
  });

  check(res, {
    'got 400/401/429': (r) => r.status === 400 || r.status === 401 || r.status === 429,
  });

  sleep(0.2);
}
