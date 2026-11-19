const childProcess = require('node:child_process');
const dns = require('node:dns').promises;

module.exports = async function checkTls({ github, context, core, domain }) {
  if (typeof domain !== 'string' || domain.length > 253 ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(domain)) {
    throw new Error('SITE_DOMAIN must be a bare DNS hostname, without a scheme, port or path.');
  }
  domain = domain.toLowerCase();
  const hosts = [domain, domain.startsWith('www.') ? domain.slice(4) : `www.${domain}`];
  const rows = [['Check', 'Result']];

  try {
    const { data } = await github.rest.repos.getPages({
      ...context.repo,
      request: { timeout: 15000 },
    });
    const cert = data.https_certificate;
    const expires = Date.parse(cert?.expires_at);
    const daysLeft = (expires - Date.now()) / 86400000;
    const detail = `state=${cert?.state ?? 'missing'}, expires=${cert?.expires_at ?? 'unknown'}`;
    rows.push(['GitHub Pages certificate', detail]);
    core.info(detail);
    if (data.cname !== domain) {
      core.setFailed(`Pages custom domain is ${data.cname}, expected ${domain}.`);
    }
    if (!['issued', 'uploaded', 'approved'].includes(cert?.state)) {
      core.setFailed(`Pages certificate is not ready: ${detail}. ${cert?.description ?? ''}`);
    }
    if (!Number.isFinite(expires) || daysLeft <= 21) {
      core.setFailed(`Pages certificate is expired, missing or within 21 days of expiry: ${detail}.`);
    }
  } catch (error) {
    core.setFailed(`Cannot read GitHub Pages certificate: ${error.message}`);
    rows.push(['GitHub Pages certificate', 'API request failed; see logs']);
  }

  const originHostname = `${context.repo.owner.toLowerCase()}.github.io`;
  let origins = [];
  try {
    origins = await dns.resolve4(originHostname);
    if (!origins.length) throw new Error('No IPv4 addresses returned');
    core.info(`GitHub Pages origins from ${originHostname}: ${origins.join(', ')}`);
  } catch (error) {
    core.setFailed(`Cannot discover GitHub Pages origins for ${originHostname}: ${error.message}`);
    rows.push(['Origin DNS lookup', 'Failed; see logs']);
  }

  for (const origin of [null, ...origins]) {
    for (const host of hosts) {
      const label = `${host} via ${origin ?? 'Cloudflare'}`;
      const args = [
        '--silent', '--show-error',
        '--location', '--max-redirs', '3',
        '--proto', '=https', '--proto-redir', '=https',
        '--connect-timeout', '10', '--max-time', '20',
        '--output', '/dev/null',
        '--write-out', '{"transfer":%{json},"headers":%{header_json}}',
      ];
      if (origin) {
        // Preserve hostname/SNI, including www redirects, without using public DNS.
        args.push('--noproxy', '*');
        for (const name of hosts) args.push('--resolve', `${name}:443:${origin}`);
      }
      args.push(`https://${host}/`);
      const result = childProcess.spawnSync('curl', args, { encoding: 'utf8', timeout: 25000 });
      if (result.error) {
        core.setFailed(`${label}: curl could not complete: ${result.error.message}`);
        rows.push([label, 'curl execution failed; see logs']);
        continue;
      }
      const { transfer, headers } = JSON.parse(result.stdout);
      const http = String(transfer.http_code).padStart(3, '0');
      const detail = `HTTP ${http}, curl exit ${result.status}, remote IP ${transfer.remote_ip}`;
      rows.push([label, detail]);
      core.info(`${label}: ${detail}`);
      if (result.status !== 0) {
        core.setFailed(`${label}: ${detail}. ${result.stderr.trim()}`);
      } else if (transfer.http_code !== 200 || transfer.url_effective !== `https://${domain}/`) {
        core.setFailed(`${label}: unexpected response: ${detail}, final URL ${transfer.url_effective}`);
      } else if (!origin && !headers['cf-ray']?.length) {
        core.setFailed(`${label}: response did not include a Cloudflare cf-ray header.`);
      }
    }
  }

  await core.summary.addHeading('TLS health (read-only)').addTable(rows).write();
};
