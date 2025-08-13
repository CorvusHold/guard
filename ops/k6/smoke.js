import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 5,
  duration: '1m',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<300'],
  },
};

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:8080';

export default function () {
  const livez = http.get(`${BASE_URL}/livez`, { timeout: '5s' });
  check(livez, { 'livez 200': (r) => r.status === 200 });

  const readyz = http.get(`${BASE_URL}/readyz`, { timeout: '5s' });
  check(readyz, { 'readyz 200': (r) => r.status === 200 });

  // Optional: Swagger UI
  const swagger = http.get(`${BASE_URL}/swagger/index.html`, { timeout: '5s' });
  check(swagger, { 'swagger 200': (r) => r.status === 200 });

  sleep(1);
}
