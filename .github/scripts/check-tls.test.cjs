const assert = require('node:assert/strict');
const { test } = require('node:test');
const childProcess = require('node:child_process');
const dns = require('node:dns').promises;
const checkTls = require('./check-tls.cjs');

const now = Date.parse('2026-11-19T00:00:00Z');
const healthyCertificate = { state: 'approved', expires_at: '2027-01-01' };
const domain = 'example.com';
const originAddresses = ['192.0.2.10', '192.0.2.20'];
const response = (code = 200, overrides = {}) => ({
  status: 0,
  stderr: '',
  stdout: JSON.stringify({
    transfer: { http_code: code, remote_ip: originAddresses[0], url_effective: `https://${domain}/` },
    headers: { 'cf-ray': ['test-ray'] },
  }),
  ...overrides,
});

async function run(t, {
  certificate = healthyCertificate, curl = () => response(), apiError,
  siteDomain = domain, pagesDomain = siteDomain, owner = 'example',
  addresses = originAddresses, dnsError, httpsEnforced = true,
} = {}) {
  t.mock.method(Date, 'now', () => now);
  const calls = [];
  const lookups = [];
  t.mock.method(dns, 'resolve4', async hostname => {
    lookups.push(hostname);
    if (dnsError) throw dnsError;
    return addresses;
  });
  t.mock.method(childProcess, 'spawnSync', (command, args) => {
    assert.equal(command, 'curl');
    calls.push(args);
    return curl(args);
  });
  const failures = [];
  const logs = [];
  const summary = { addHeading() { return this; }, addTable() { return this; }, async write() {} };
  await checkTls({
    github: { rest: { repos: { async getPages() {
      if (apiError) throw apiError;
      return { data: { cname: pagesDomain, https_enforced: httpsEnforced, https_certificate: certificate } };
    } } } },
    context: { repo: { owner, repo: 'example' } },
    domain: siteDomain,
    core: { setFailed: message => failures.push(message), info: message => logs.push(message), summary },
  });
  return { failures, logs, calls, lookups };
}

test('healthy checks follow www redirects and pin both hostnames at every origin', async t => {
  const { failures, calls, lookups } = await run(t);
  assert.deepEqual(failures, []);
  assert.deepEqual(lookups, ['example.github.io']);
  for (const host of [domain, `www.${domain}`]) {
    const probes = calls.filter(args => args.at(-1) === `https://${host}/`);
    assert.equal(probes.length, originAddresses.length + 1);
    for (const args of probes) {
      assert.ok(args.includes('--location'));
      assert.ok(!args.includes('--insecure'));
      if (args.includes('--resolve')) {
        const ip = args[args.indexOf('--resolve') + 1].split(':').at(-1);
        assert.ok(originAddresses.includes(ip));
        assert.ok(args.includes(`${domain}:443:${ip}`));
        assert.ok(args.includes(`www.${domain}:443:${ip}`));
      }
    }
  }
});

test('expiry threshold, missing expiry and bad authorization fail the monitor', async t => {
  for (const [certificate, expectedFailure] of [
    [{ state: 'issued', expires_at: '2026-12-11' }, false],
    [{ state: 'issued', expires_at: '2026-12-10' }, true],
    [{ state: 'issued', expires_at: '2026-11-12' }, true],
    [{ state: 'issued' }, true],
    [{ state: 'bad_authz', expires_at: '2027-01-01' }, true],
  ]) {
    await t.test(JSON.stringify(certificate), async child => {
      const { failures } = await run(child, { certificate });
      assert.equal(failures.length > 0, expectedFailure);
    });
  }
});

test('expired origin TLS logs HTTP 000 once and retains the curl error', async t => {
  const { failures, logs } = await run(t, {
    curl: args => args.includes('--resolve') && args.at(-1).includes('www.')
      ? response(0, { status: 60, stderr: 'curl: (60) SSL certificate problem: certificate has expired' })
      : response(),
  });
  assert.ok(failures.some(message => message.includes('HTTP 000, curl exit 60')));
  assert.ok(failures.some(message => message.includes('certificate has expired')));
  assert.ok(!logs.join('\n').includes('000000'));
});

test('Cloudflare HTTP errors, missing proxy headers and redirects to another site fail', async t => {
  for (const invalid of [
    response(526),
    response(301),
    response(200, { stdout: JSON.stringify({ transfer: { http_code: 200, url_effective: `https://${domain}/` }, headers: {} }) }),
    response(200, { stdout: JSON.stringify({ transfer: { http_code: 200, url_effective: 'https://other.example/' }, headers: { 'cf-ray': ['test'] } }) }),
  ]) {
    await t.test(invalid.stdout, async child => {
      const { failures } = await run(child, { curl: () => invalid });
      assert.ok(failures.length > 0);
    });
  }
});

test('API failure still checks public and origin endpoints without passing the run', async t => {
  const { failures, calls } = await run(t, { apiError: new Error('HTTP 403') });
  assert.ok(failures.some(message => message.includes('Cannot read GitHub Pages certificate: HTTP 403')));
  assert.equal(calls.length, 2 * (originAddresses.length + 1));
});

test('curl execution failures are reported instead of treated as HTTP success', async t => {
  const { failures } = await run(t, { curl: () => ({ error: new Error('spawnSync curl ETIMEDOUT') }) });
  assert.ok(failures.some(message => message.includes('ETIMEDOUT')));
});

test('changed domain, owner and DNS answers are used without production defaults', async t => {
  const siteDomain = 'www.another.example';
  const { failures, calls, lookups } = await run(t, {
    siteDomain, owner: 'AnotherOwner', addresses: ['198.51.100.7'],
    curl: () => response(200, { stdout: JSON.stringify({
      transfer: { http_code: 200, url_effective: `https://${siteDomain}/` },
      headers: { 'cf-ray': ['test'] },
    }) }),
  });
  assert.deepEqual(failures, []);
  assert.deepEqual(lookups, ['anotherowner.github.io']);
  assert.equal(calls.length, 4);
  assert.ok(calls.some(args => args.includes('www.another.example:443:198.51.100.7')));
  assert.ok(calls.some(args => args.includes('another.example:443:198.51.100.7')));
  assert.ok(!calls.some(args => args.join(' ').includes('www.www.')));
});

test('DNS failure or empty answers fail explicitly and never fall back to preset origins', async t => {
  for (const options of [{ dnsError: new Error('ENOTFOUND') }, { addresses: [] }]) {
    await t.test(JSON.stringify(options), async child => {
      const { failures, calls } = await run(child, options);
      assert.ok(failures.some(message => message.includes('Cannot discover GitHub Pages origins')));
      assert.equal(calls.length, 2);
      assert.ok(calls.every(args => !args.includes('--resolve')));
    });
  }
});

test('missing or invalid SITE_DOMAIN fails before any network calls', async t => {
  for (const siteDomain of ['', 'https://example.com', 'example.com/path', 'example.com:443']) {
    await t.test(siteDomain, async child => {
      await assert.rejects(run(child, { siteDomain }), /SITE_DOMAIN must be a bare DNS hostname/);
      assert.equal(dns.resolve4.mock.callCount(), 0);
      assert.equal(childProcess.spawnSync.mock.callCount(), 0);
    });
  }
});

test('Pages domain drift is checked against the configured variable', async t => {
  const { failures } = await run(t, { pagesDomain: 'wrong.example' });
  assert.ok(failures.some(message => message.includes('Pages custom domain is wrong.example, expected example.com')));
});

test('Pages HTTPS enforcement drift fails the monitor', async t => {
  const { failures } = await run(t, { httpsEnforced: false });
  assert.ok(failures.some(message => message.includes('HTTPS enforcement is disabled')));
});
