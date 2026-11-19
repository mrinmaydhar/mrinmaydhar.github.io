'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const recoverTls = require('./recover-tls.cjs');

const domain = 'example.com';
const owner = 'example';
const origins = ['192.0.2.10', '192.0.2.20'];
const zoneId = 'a'.repeat(32);
const now = Date.parse('2026-11-19T00:00:00Z');
const id = host => Buffer.from(host).subarray(0, 16).toString('hex').padEnd(32, '0');
const records = () => [domain, `www.${domain}`].map(host => ({
  id: id(host), type: 'CNAME', name: host, content: `${owner}.github.io`, ttl: 1, proxied: true,
}));
const pages = broken => ({
  cname: domain,
  protected_domain_state: 'verified',
  https_enforced: true,
  https_certificate: {
    state: broken ? 'bad_authz' : 'approved',
    expires_at: broken ? '2026-11-12' : '2027-01-01',
    domains: [domain, `www.${domain}`],
  },
});
const curl = (httpCode = 200, tlsError = false, cfRay = true) => ({
  status: tlsError ? 60 : 0,
  stderr: tlsError ? 'curl: (60) SSL certificate expired' : '',
  stdout: JSON.stringify({
    transfer: { http_code: httpCode, url_effective: `https://${domain}/`, remote_ip: origins[0] },
    headers: cfRay ? { 'cf-ray': ['ray'] } : {},
  }),
});

function fixture({
  broken = false,
  directTlsError = false,
  dnsRecords = records(),
  returnAllRecords = false,
  pagesPreflightFailures = 0,
  pagesPreflightError,
  pagesDetachFailures = 0,
  pagesDetachAfterApplyFailures = 0,
  pagesRestoreFailures = 0,
  patchFailure,
  publicHttp = 200,
  staleDnsChecks = 0,
  dnsAttempts = 1,
} = {}) {
  const state = {
    pages: pages(broken),
    directTlsError,
    patches: [],
    pagesUpdates: [],
    pageRequests: [],
    requests: [],
    dnsChecks: new Map(),
    proxies: new Map(dnsRecords.map(record => [record.id, record.proxied])),
    summary: [],
  };

  const github = {
    rest: { repos: { getPages: async () => ({ data: structuredClone(state.pages) }) } },
    async request(route, request) {
      assert.equal(route, 'PUT /repos/{owner}/{repo}/pages');
      state.pagesUpdates.push(request.cname);
      state.pageRequests.push({
        cname: request.cname,
        https_enforced: request.https_enforced,
      });
      if (state.pagesUpdates.length === 1) {
        if (pagesPreflightError) throw pagesPreflightError;
        if (pagesPreflightFailures-- > 0) throw new Error('Pages permission denied');
        return { status: 204 };
      }
      if (request.cname === null) {
        if (pagesDetachFailures-- > 0) throw new Error('Pages detach failed');
        state.pages.cname = null;
        state.pages.https_certificate = null;
        if (pagesDetachAfterApplyFailures-- > 0) throw new Error('Pages detach response lost');
      } else if (pagesRestoreFailures-- > 0) {
        throw new Error('Pages restore failed');
      } else {
        if (request.https_enforced === undefined) {
          state.pages = pages(false);
          state.pages.https_enforced = false;
          state.directTlsError = false;
        } else {
          state.pages.https_enforced = request.https_enforced;
        }
      }
      return { status: 204 };
    },
  };

  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    const body = options.body ? JSON.parse(options.body) : undefined;
    state.requests.push({ method: options.method, path: parsed.pathname, body });
    if (options.method === 'GET') {
      assert.equal(parsed.searchParams.get('type'), 'CNAME');
      const host = parsed.searchParams.get('name.exact');
      const result = returnAllRecords ? dnsRecords : dnsRecords.filter(record => record.name === host);
      return response({ success: true, result });
    }
    assert.equal(options.method, 'PATCH');
    assert.deepEqual(Object.keys(body), ['proxied']);
    const recordId = parsed.pathname.split('/').at(-1);
    const patch = { id: recordId, proxied: body.proxied };
    state.patches.push(patch);
    if (patchFailure?.(patch)) return response({ success: false, errors: [{ message: 'PATCH failed' }] }, false);
    state.proxies.set(recordId, body.proxied);
    const record = dnsRecords.find(candidate => candidate.id === recordId);
    record.proxied = body.proxied;
    return response({ success: true, result: { ...record, proxied: body.proxied } });
  };

  const core = {
    info() {},
    warning() {},
    summary: {
      addHeading() { return this; },
      addTable(rows) { state.summary = rows; return this; },
      addRaw(text) { state.summary.push(text); return this; },
      async write() {},
    },
  };
  const resolve4 = async hostname => {
    if (hostname === `${owner}.github.io`) return origins;
    if ([domain, `www.${domain}`].includes(hostname)) {
      const checks = state.dnsChecks.get(hostname) || 0;
      state.dnsChecks.set(hostname, checks + 1);
      return checks < staleDnsChecks ? ['203.0.113.10'] : origins;
    }
    throw new Error(`Unexpected DNS lookup: ${hostname}`);
  };
  const spawnSync = (_command, args) => args.includes('--resolve')
    ? curl(200, state.directTlsError)
    : curl(publicHttp);
  const options = {
    github,
    context: { repo: { owner, repo: 'site' } },
    core,
    domain,
    zoneId,
    cloudflareToken: 'secret',
    fetchImpl,
    resolve4,
    spawnSync,
    sleep: async () => {},
    now: () => now,
    timing: {
      dnsAttempts,
      dnsDelayMs: 0,
      certificateAttempts: 1,
      publicAttempts: 1,
      detachDelayMs: 0,
    },
  };
  return { state, run: () => recoverTls(options) };
}

function response(payload, ok = true) {
  return {
    ok,
    status: ok ? 200 : 403,
    async json() { return payload; },
  };
}

test('healthy Pages certificate skips all production writes', async () => {
  const f = fixture();
  assert.deepEqual(await f.run(), { recovered: false, reason: 'healthy' });
  assert.deepEqual(f.state.patches, []);
  assert.deepEqual(f.state.pagesUpdates, []);
});

test('recovery changes only the two allowed CNAME proxy flags and restores them', async () => {
  const targets = records();
  const unrelated = [
    { id: 'c'.repeat(32), type: 'TXT', name: '_verify.example.com', content: 'keep' },
    { id: 'd'.repeat(32), type: 'A', name: 'api.example.com', content: '198.51.100.4', proxied: true },
    { id: 'e'.repeat(32), type: 'CNAME', name: 'mail.example.com', content: 'provider.example', proxied: true },
  ];
  const f = fixture({
    broken: true,
    directTlsError: true,
    dnsRecords: [...targets, ...unrelated],
    returnAllRecords: true,
  });
  assert.deepEqual(await f.run(), { recovered: true, reason: 'certificate_recovered' });
  assert.deepEqual(f.state.patches.map(patch => patch.proxied), [false, false, true, true]);
  assert.deepEqual(new Set(f.state.patches.map(patch => patch.id)), new Set(targets.map(record => record.id)));
  assert.deepEqual(f.state.pagesUpdates, [domain, null, domain, domain]);
  assert.deepEqual(f.state.pageRequests.slice(1), [
    { cname: null, https_enforced: undefined },
    { cname: domain, https_enforced: undefined },
    { cname: domain, https_enforced: true },
  ]);
  assert.equal(f.state.requests.filter(request => request.method === 'GET').length, 4);
  for (const record of unrelated) assert.equal(f.state.proxies.get(record.id), record.proxied);
  const patches = f.state.requests.filter(request => request.method === 'PATCH');
  assert.ok(patches.every(request => Object.keys(request.body).length === 1 && typeof request.body.proxied === 'boolean'));
  assert.ok(f.state.requests.every(request => request.method === 'GET' || request.method === 'PATCH'));
});

test('direct certificate verification can trigger recovery without stale Pages metadata', async () => {
  const f = fixture({ directTlsError: true });
  assert.equal((await f.run()).recovered, true);
});

test('HTTPS enforcement is sent only after the replacement certificate is ready', async () => {
  const f = fixture({ broken: true, directTlsError: true });
  f.state.pages.https_enforced = false;
  await f.run();

  assert.deepEqual(f.state.pageRequests, [
    { cname: domain, https_enforced: false },
    { cname: null, https_enforced: undefined },
    { cname: domain, https_enforced: undefined },
    { cname: domain, https_enforced: true },
  ]);
});

test('Pages token preflight fails before Cloudflare is changed', async () => {
  const f = fixture({
    broken: true,
    directTlsError: true,
    pagesPreflightFailures: 1,
  });
  await assert.rejects(f.run(), /PAGES_RECOVERY_TOKEN cannot manage GitHub Pages settings/);
  assert.deepEqual(f.state.pagesUpdates, [domain]);
  assert.deepEqual(f.state.patches, []);
});

test('an authorized 409 from in-progress certificate issuance continues recovery', async () => {
  const error = Object.assign(
    new Error('The certificate has not finished being issued'),
    { status: 409 },
  );
  const f = fixture({
    broken: true,
    directTlsError: true,
    pagesPreflightError: error,
  });
  assert.equal((await f.run()).recovered, true);
  assert.deepEqual(f.state.pagesUpdates, [domain, null, domain, domain]);
  assert.equal(f.state.pages.https_enforced, true);
});

test('other Pages preflight 409 responses still stop before Cloudflare changes', async () => {
  const error = Object.assign(new Error('A different conflict occurred'), { status: 409 });
  const f = fixture({
    broken: true,
    directTlsError: true,
    pagesPreflightError: error,
  });
  await assert.rejects(f.run(), /PAGES_RECOVERY_TOKEN cannot manage/);
  assert.deepEqual(f.state.patches, []);
});

test('recursive DNS cache is allowed to expire beyond the five-minute TTL', async () => {
  const f = fixture({
    broken: true,
    directTlsError: true,
    staleDnsChecks: 21,
    dnsAttempts: 25,
  });
  assert.equal((await f.run()).recovered, true);
  assert.deepEqual([...f.state.dnsChecks.values()], [22, 22]);
});

test('Pages configuration drift aborts before Cloudflare changes', async () => {
  for (const pagesOverride of [{ cname: 'other.example' }, { protected_domain_state: 'unverified' }]) {
    const f = fixture({ broken: true, directTlsError: true });
    Object.assign(f.state.pages, pagesOverride);
    await assert.rejects(f.run(), /refusing recovery/i);
    assert.deepEqual(f.state.patches, []);
    assert.deepEqual(f.state.pagesUpdates, []);
  }
});

test('healthy certificate restores disabled HTTPS enforcement without DNS changes', async () => {
  const f = fixture();
  f.state.pages.https_enforced = false;
  assert.deepEqual(await f.run(), { recovered: true, reason: 'https_enforcement_restored' });
  assert.deepEqual(f.state.pagesUpdates, [domain, domain]);
  assert.deepEqual(f.state.patches, []);
  assert.equal(f.state.pages.https_enforced, true);
});

test('missing, redirected, duplicate, or malformed CNAMEs abort before writes', async () => {
  const duplicate = records();
  duplicate.push({ ...duplicate[0], id: 'a'.repeat(32) });
  const malformed = records();
  malformed[0].id = 'invalid';
  const cases = [
    records().slice(0, 1),
    [{ ...records()[0], content: 'other.example' }, records()[1]],
    duplicate,
    malformed,
  ];
  for (const dnsRecords of cases) {
    const f = fixture({ broken: true, directTlsError: true, dnsRecords });
    await assert.rejects(f.run(), /refusing recovery/i);
    assert.deepEqual(f.state.patches, []);
    assert.deepEqual(f.state.pagesUpdates, []);
  }
});

test('Pages and DNS state roll back after a Pages failure', async () => {
  const f = fixture({ broken: true, directTlsError: true, pagesRestoreFailures: 1 });
  await assert.rejects(f.run(), /Pages restore failed/);
  assert.deepEqual(f.state.pagesUpdates, [domain, null, domain, domain]);
  assert.deepEqual(f.state.patches.map(patch => patch.proxied), [false, false, true, true]);
  assert.equal(f.state.pages.cname, domain);
});

test('an ambiguous Pages detach restores the custom domain before proxying resumes', async () => {
  const f = fixture({
    broken: true,
    directTlsError: true,
    pagesDetachAfterApplyFailures: 1,
  });
  await assert.rejects(f.run(), /Pages detach response lost/);
  assert.deepEqual(f.state.pagesUpdates, [domain, null, domain]);
  assert.deepEqual(f.state.patches.map(patch => patch.proxied), [false, false, true, true]);
  assert.equal(f.state.pages.cname, domain);
});

test('an uncertain Cloudflare write is rolled back, and rollback retries', async () => {
  const failed = new Set();
  const f = fixture({
    broken: true,
    directTlsError: true,
    patchFailure: patch => {
      const key = `${patch.id}:${patch.proxied}`;
      if ((patch.id === id(`www.${domain}`) && !patch.proxied) ||
          (patch.proxied && !failed.has(key))) {
        failed.add(key);
        return true;
      }
      return false;
    },
  });
  await assert.rejects(f.run(), /PATCH failed/);
  assert.deepEqual([...f.state.proxies.values()], [true, true]);
  assert.deepEqual(f.state.pagesUpdates, [domain]);
});

test('Cloudflare 526 fails after original proxying and Pages domain are restored', async () => {
  const f = fixture({ broken: true, directTlsError: true, publicHttp: 526 });
  await assert.rejects(f.run(), /Cloudflare still returns 526/);
  assert.equal(f.state.pages.cname, domain);
  assert.deepEqual([...f.state.proxies.values()], [true, true]);
  assert.deepEqual(f.state.pagesUpdates, [domain, null, domain, domain]);
  assert.equal(f.state.pages.https_enforced, true);
});
