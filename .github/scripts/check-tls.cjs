'use strict';

const { getOrigins, getPages, hostsFor, probeHttps, validateDomain } = require('./tls-common.cjs');

module.exports = async function checkTls({ github, context, core, domain }) {
  domain = validateDomain(domain);
  const hosts = hostsFor(domain);
  const rows = [['Check', 'Result']];

  try {
    const pages = await getPages(github, context);
    const cert = pages.https_certificate;
    const expires = Date.parse(cert?.expires_at);
    const daysLeft = (expires - Date.now()) / 86400000;
    const detail = `state=${cert?.state ?? 'missing'}, expires=${cert?.expires_at ?? 'unknown'}`;
    rows.push(['GitHub Pages certificate', detail]);
    core.info(detail);
    if (pages.cname !== domain) {
      core.setFailed(`Pages custom domain is ${pages.cname}, expected ${domain}.`);
    }
    if (pages.https_enforced !== true) {
      core.setFailed('Pages HTTPS enforcement is disabled.');
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

  let origins = [];
  try {
    const discovered = await getOrigins(context.repo.owner);
    origins = discovered.addresses;
    core.info(`GitHub Pages origins from ${discovered.hostname}: ${origins.join(', ')}`);
  } catch (error) {
    core.setFailed(`Cannot discover GitHub Pages origins for ${context.repo.owner.toLowerCase()}.github.io: ${error.message}`);
    rows.push(['Origin DNS lookup', 'Failed; see logs']);
  }

  for (const origin of [null, ...origins]) {
    for (const host of hosts) {
      const label = `${host} via ${origin ?? 'Cloudflare'}`;
      const result = probeHttps({ host, domain, hosts, origin });
      const http = String(result.httpCode).padStart(3, '0');
      const detail = `HTTP ${http}, curl exit ${result.curlCode}, remote IP ${result.remoteIp ?? ''}`;
      rows.push([label, detail]);
      core.info(`${label}: ${detail}`);
      if (result.curlCode !== 0) {
        core.setFailed(`${label}: ${detail}. ${result.stderr || result.message}`);
      } else if (result.httpCode !== 200 || result.finalUrl !== `https://${domain}/`) {
        core.setFailed(`${label}: unexpected response: ${detail}, final URL ${result.finalUrl}`);
      } else if (!origin && !result.cfRay) {
        core.setFailed(`${label}: response did not include a Cloudflare cf-ray header.`);
      }
    }
  }

  await core.summary.addHeading('TLS health (read-only)').addTable(rows).write();
};
