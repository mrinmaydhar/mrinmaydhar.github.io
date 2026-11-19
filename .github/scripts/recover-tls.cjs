'use strict';

const {
  getOrigins,
  getPages,
  hostsFor,
  normalizeDnsName,
  probeHttps,
  validateDomain,
} = require('./tls-common.cjs');

const READY = new Set(['issued', 'uploaded', 'approved']);
const TLS_ERRORS = new Set([51, 60]);
const LIMITS = Object.freeze({
  dnsAttempts: 41,
  dnsDelayMs: 15_000,
  detachDelayMs: 5_000,
  certificateAttempts: 61,
  certificateDelayMs: 60_000,
  publicAttempts: 20,
  publicDelayMs: 15_000,
});

function validatePages(pages, domain) {
  if (normalizeDnsName(pages.cname) !== domain) {
    throw new Error(`Pages custom domain is ${pages.cname || '<missing>'}, expected ${domain}; refusing recovery.`);
  }
  if (pages.protected_domain_state !== 'verified') {
    throw new Error(`Pages domain is not verified; refusing recovery.`);
  }
  if (pages.https_enforced !== true) {
    throw new Error('Pages HTTPS enforcement is disabled; refusing recovery.');
  }
}

function needsCertificate(pages, now) {
  const expires = Date.parse(pages.https_certificate?.expires_at);
  return pages.https_certificate?.state === 'bad_authz' ||
    (Number.isFinite(expires) && expires <= now);
}

function certificateReady(pages, hosts, domain, now) {
  const cert = pages.https_certificate;
  const domains = new Set((cert?.domains || []).map(normalizeDnsName));
  return normalizeDnsName(pages.cname) === domain &&
    pages.protected_domain_state === 'verified' &&
    pages.https_enforced === true &&
    READY.has(cert?.state) &&
    Date.parse(cert.expires_at) > now &&
    hosts.every(host => domains.has(host));
}

async function updatePages(github, context, cname, httpsEnforced) {
  const body = { ...context.repo, cname, request: { timeout: 30_000 } };
  if (httpsEnforced !== undefined) body.https_enforced = httpsEnforced;
  await github.request('PUT /repos/{owner}/{repo}/pages', body);
}

async function preflightPagesAccess(github, context, pages) {
  try {
    await updatePages(github, context, pages.cname, pages.https_enforced);
  } catch (error) {
    throw new Error(
      `PAGES_RECOVERY_TOKEN cannot manage GitHub Pages settings; refusing to change DNS: ${error.message}`,
      { cause: error },
    );
  }
}

async function retry(action, sleep, attempts = 3) {
  let error;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await action();
    } catch (caught) {
      error = caught;
      if (attempt < attempts) await sleep(1_000);
    }
  }
  throw error;
}

async function cfRequest({ fetchImpl, token, zoneId }, path, method = 'GET', body) {
  if ((method === 'GET' && !/^dns_records\?/.test(path)) ||
      (method === 'PATCH' &&
        (!/^dns_records\/[0-9a-f]{32}$/i.test(path) ||
         !body || Object.keys(body).length !== 1 ||
         typeof body.proxied !== 'boolean')) ||
      !['GET', 'PATCH'].includes(method)) {
    throw new Error(`Refusing unsafe Cloudflare request: ${method} ${path}.`);
  }

  // /client/v4 is Cloudflare's service API contract, not a dependency version.
  const response = await fetchImpl(`https://api.cloudflare.com/client/v4/zones/${zoneId}/${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Cloudflare returned HTTP ${response.status} without JSON.`);
  }
  if (!response.ok || payload.success === false) {
    throw new Error(
      `Cloudflare HTTP ${response.status}: ${(payload.errors || []).map(error => error.message || error).join('; ') || 'unknown error'}.`,
    );
  }
  return payload.result;
}

async function siteRecords(client, hosts, originHostname) {
  const entries = [];
  for (const host of hosts) {
    const query = new URLSearchParams({
      type: 'CNAME',
      'name.exact': host,
      match: 'all',
      per_page: '100',
    });
    const found = (await cfRequest(client, `dns_records?${query}`) || []).filter(record =>
      record.type === 'CNAME' && normalizeDnsName(record.name) === host,
    );
    if (found.length !== 1 || normalizeDnsName(found[0].content) !== originHostname) {
      throw new Error(`Expected one CNAME for ${host} pointing to ${originHostname}; refusing recovery.`);
    }
    const record = found[0];
    if (!/^[0-9a-f]{32}$/i.test(record.id || '') || typeof record.proxied !== 'boolean') {
      throw new Error(`Cloudflare CNAME for ${host} lacks a valid ID or proxy state; refusing recovery.`);
    }
    entries.push({ record: { ...record, host }, originalProxy: record.proxied, touched: false });
  }
  if (new Set(entries.map(entry => entry.record.id)).size !== 2) {
    throw new Error('Cloudflare did not return two distinct Pages CNAME IDs; refusing recovery.');
  }
  return entries;
}

async function setProxy(client, entry, proxied) {
  const { record } = entry;
  const allowed = client.allowlist.get(record.id);
  if (!allowed || allowed !== `${record.host}|CNAME|${normalizeDnsName(record.content)}` ||
      normalizeDnsName(record.name) !== record.host ||
      normalizeDnsName(record.content) !== client.originHostname) {
    throw new Error(`Refusing Cloudflare mutation for an unverified record: ${record.id}.`);
  }
  entry.touched = true;
  const result = await cfRequest(client, `dns_records/${record.id}`, 'PATCH', { proxied });
  if (result?.proxied !== proxied) throw new Error(`Cloudflare did not confirm proxy=${proxied} for ${record.host}.`);
  record.proxied = proxied;
  entry.touched = proxied !== entry.originalProxy;
}

async function wait(name, { attempts, delayMs, sleep, check }) {
  let last = '';
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const result = await check();
    if (result.ok) return result.value;
    last = result.message;
    if (attempt < attempts) await sleep(delayMs);
  }
  throw new Error(`${name}: ${last}`);
}

function probe(options, host, origin) {
  return probeHttps({ ...options, host, origin });
}

async function waitForDns(options, hosts, origins, limits) {
  const allowed = new Set(origins);
  return wait('GitHub Pages DNS did not converge', {
    attempts: limits.dnsAttempts,
    delayMs: limits.dnsDelayMs,
    sleep: options.sleep,
    check: async () => {
      const errors = [];
      for (const host of hosts) {
        try {
          const addresses = await options.resolve4(host);
          if (!addresses.length || addresses.some(address => !allowed.has(address))) {
            errors.push(`${host}=${addresses.join(', ') || '<none>'}`);
          }
        } catch (error) {
          errors.push(`${host}: ${error.message}`);
        }
      }
      return { ok: !errors.length, message: errors.join('; ') };
    },
  });
}

async function verifyDnsOnly(client, entries, hosts, originHostname, sleep) {
  const current = await retry(() => siteRecords(client, hosts, originHostname), sleep);
  const expected = new Map(entries.map(entry => [entry.record.id, entry.record.host]));
  const errors = current.flatMap(entry => {
    const host = expected.get(entry.record.id);
    return host && entry.record.host === host && entry.record.proxied === false
      ? []
      : [`${entry.record.host} is not the expected DNS-only Pages record`];
  });
  if (errors.length || current.length !== 2) {
    throw new Error(`Cloudflare did not confirm both Pages CNAMEs are DNS-only: ${errors.join('; ')}`);
  }
}

function verifyOrigin(options, hosts, origins) {
  const failures = [];
  for (const origin of origins) {
    for (const host of hosts) {
      const result = probe(options, host, origin);
      if (!result.ok) failures.push(`${host} via ${origin}: ${result.message}${result.stderr ? `; ${result.stderr}` : ''}`);
    }
  }
  if (failures.length) throw new Error(`Origin TLS verification failed:\n${failures.join('\n')}`);
}

async function rollback(client, entries, detached, restoreDomain, sleep) {
  const errors = [];
  if (detached) {
    try {
      await retry(restoreDomain, sleep);
    } catch (error) {
      errors.push(`restore Pages custom domain: ${error.message}`);
    }
  }
  for (const entry of entries.filter(candidate => candidate.touched)) {
    try {
      await retry(() => setProxy(client, entry, entry.originalProxy), sleep);
    } catch (error) {
      errors.push(`restore ${entry.record.host} proxy state: ${error.message}`);
    }
  }
  return errors;
}

module.exports = async function recoverTls({
  github,
  context,
  core,
  domain: rawDomain,
  zoneId,
  cloudflareToken,
  fetchImpl = globalThis.fetch,
  spawnSync,
  resolve4,
  sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
  now = () => Date.now(),
  timing = {},
} = {}) {
  const limits = { ...LIMITS, ...timing };
  const domain = validateDomain(rawDomain);
  const hosts = hostsFor(domain);
  const probeOptions = { domain, hosts, spawnSync };
  let entries = [];
  let detached = false;
  let client;

  try {
    const pages = await getPages(github, context);
    validatePages(pages, domain);
    const {
      hostname: originHostname,
      addresses: origins,
      resolve4: resolveHost,
    } = await getOrigins(context.repo.owner, resolve4);
    const directResults = hosts.flatMap(host =>
      origins.map(origin => probe(probeOptions, host, origin)),
    );
    if (!needsCertificate(pages, now()) && !directResults.some(result => TLS_ERRORS.has(result.curlCode))) {
      return { recovered: false, reason: 'healthy' };
    }

    if (!/^[0-9a-f]{32}$/i.test(zoneId || '') || !cloudflareToken) {
      throw new Error('Cloudflare zone ID or environment token is missing or invalid.');
    }
    client = { fetchImpl, token: cloudflareToken, zoneId, originHostname };
    entries = await siteRecords(client, hosts, originHostname);
    client.allowlist = new Map(entries.map(({ record }) => [
      record.id,
      `${record.host}|CNAME|${normalizeDnsName(record.content)}`,
    ]));

    await preflightPagesAccess(github, context, pages);

    let operationError;
    try {
      for (const entry of entries) {
        if (entry.originalProxy) await setProxy(client, entry, false);
      }
      await verifyDnsOnly(client, entries, hosts, originHostname, sleep);
      await waitForDns({ resolve4: resolveHost, sleep }, hosts, origins, limits);

      await updatePages(github, context, null);
      detached = true;
      await sleep(limits.detachDelayMs);
      await updatePages(github, context, domain, true);
      detached = false;

      const certificate = await wait('GitHub Pages did not issue a valid certificate', {
        attempts: limits.certificateAttempts,
        delayMs: limits.certificateDelayMs,
        sleep,
        check: async () => {
          const current = await getPages(github, context);
          const cert = current.https_certificate;
          return {
            ok: certificateReady(current, hosts, domain, now()),
            value: current,
            message: `state=${cert?.state || 'missing'}, expires=${cert?.expires_at || 'unknown'}`,
          };
        },
      });
      core.info(`Pages certificate: state=${certificate.https_certificate.state}, expires=${certificate.https_certificate.expires_at}`);
      verifyOrigin(probeOptions, hosts, origins);
    } catch (error) {
      operationError = error;
    }

    const rollbackErrors = await rollback(
      client,
      entries,
      detached,
      () => updatePages(github, context, domain, true),
      sleep,
    );
    if (operationError || rollbackErrors.length) {
      const errors = [...(operationError ? [operationError] : []), ...rollbackErrors.map(message => new Error(message))];
      throw new AggregateError(errors, errors.map(error => error.message).join('\n'));
    }

    await wait('Cloudflare still sees an invalid origin', {
      attempts: limits.publicAttempts,
      delayMs: limits.publicDelayMs,
      sleep,
      check: async () => {
        const errors = [];
        for (const host of hosts) {
          const result = probe(probeOptions, host);
          const proxied = entries.find(entry => entry.record.host === host)?.originalProxy === true;
          if (result.httpCode === 526) errors.push(`${host}: Cloudflare still returns 526`);
          else if (result.curlCode !== 0 || !result.ok) errors.push(`${host}: ${result.message}`);
          else if (proxied && !result.cfRay) errors.push(`${host}: cf-ray header missing`);
        }
        return { ok: !errors.length, message: errors.join('; ') };
      },
    });
    return { recovered: true, reason: 'certificate_recovered' };
  } finally {
    await core.summary
      .addHeading('GitHub Pages TLS recovery')
      .addRaw(entries.length
        ? `Checked and restored only ${entries.map(entry => `\`${entry.record.host}\``).join(' and ')} CNAME proxy state.`
        : 'Recovery preflight stopped before any DNS write.')
      .write();
  }
};
