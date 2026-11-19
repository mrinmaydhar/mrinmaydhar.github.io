'use strict';

const childProcess = require('node:child_process');
const dns = require('node:dns').promises;

function normalizeDnsName(value) {
  return String(value ?? '').toLowerCase().replace(/\.$/, '');
}

function validateDomain(value) {
  if (typeof value !== 'string' || value.length > 253 ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value)) {
    throw new Error('SITE_DOMAIN must be a bare DNS hostname, without a scheme, port or path.');
  }
  return normalizeDnsName(value);
}

function hostsFor(domain) {
  return [domain, domain.startsWith('www.') ? domain.slice(4) : `www.${domain}`];
}

async function getPages(github, context) {
  const { data } = await github.rest.repos.getPages({
    ...context.repo,
    request: { timeout: 15_000 },
  });
  return data;
}

async function getOrigins(owner, resolve4 = dns.resolve4) {
  const hostname = `${normalizeDnsName(owner)}.github.io`;
  const addresses = await resolve4(hostname);
  if (!addresses.length) throw new Error(`No IPv4 addresses returned for ${hostname}`);
  return { hostname, addresses, resolve4 };
}

function probeHttps({
  host,
  domain,
  hosts,
  origin = null,
  spawnSync = childProcess.spawnSync,
}) {
  const args = [
    '--silent', '--show-error',
    '--location', '--max-redirs', '3',
    '--proto', '=https', '--proto-redir', '=https',
    '--connect-timeout', '10', '--max-time', '20',
    '--output', '/dev/null',
    '--write-out', '{"transfer":%{json},"headers":%{header_json}}',
  ];
  if (origin) {
    args.push('--noproxy', '*');
    for (const name of hosts) args.push('--resolve', `${name}:443:${origin}`);
  }
  args.push(`https://${host}/`);

  const result = spawnSync('curl', args, { encoding: 'utf8', timeout: 25_000 });
  if (result.error) {
    return { ok: false, curlCode: null, httpCode: 0, message: result.error.message, stderr: '' };
  }

  let transfer = {};
  let headers = {};
  try {
    ({ transfer = {}, headers = {} } = JSON.parse(result.stdout || '{}'));
  } catch {
    return {
      ok: false,
      curlCode: result.status,
      httpCode: 0,
      message: `curl returned invalid JSON: ${result.stdout}`,
      stderr: result.stderr?.trim() || '',
    };
  }

  const httpCode = Number(transfer.http_code) || 0;
  const finalUrl = transfer.url_effective;
  return {
    ok: result.status === 0 && httpCode === 200 && finalUrl === `https://${domain}/`,
    curlCode: result.status,
    httpCode,
    finalUrl,
    remoteIp: transfer.remote_ip,
    cfRay: Boolean(headers['cf-ray']?.length),
    stderr: result.stderr?.trim() || '',
    message: `HTTP ${String(httpCode).padStart(3, '0')}, curl exit ${result.status}, final URL ${finalUrl || '<none>'}`,
  };
}

module.exports = {
  getOrigins,
  getPages,
  hostsFor,
  normalizeDnsName,
  probeHttps,
  validateDomain,
};
