# Personal website

Static site hosted on GitHub Pages behind Cloudflare. [web/](web/) contains the
landing page and assets; [resume/](resume/) contains the LaTeX resume and PDF viewer.

## Contributions and CI

Use a feature branch and open a pull request targeting `main`. The main-branch
ruleset requires the **Pre-merge Quality Gate**, an up-to-date branch, and resolved
review conversations. Direct pushes, force-pushes, and branch deletion are blocked;
there are no bypass actors.

This is a solo-maintainer repository. [CODEOWNERS](.github/CODEOWNERS) requests
the owner's review on bot/contributor PRs once this file is on `main`. Formal
approvals are not required: GitHub does not allow authors to approve their own PRs.
The owner currently holds the only collaborator role with merge access.

[CI Gate](.github/workflows/checks.yml) runs on PRs to `main` and manual requests,
**not again after merge**. It uses GitHub-hosted runners and read-only permissions.
The required **Pre-merge Quality Gate** passes only if both jobs succeed:

- **Lint, security, and tests** runs the same [pre-commit hooks](.pre-commit-config.yaml)
  used locally: actionlint/ShellCheck and zizmor check changed workflows,
  check-jsonschema validates the Renovate config, and Node tests cover the TLS
  monitor. Hook/gate configuration changes and manual runs execute all hooks.
  Gitleaks scans full commit history, including secrets added and later removed.
- **Build site** runs the same [build](.github/workflows/build-site.yml) as
  deployment: it compiles the resume when its inputs change, then packages the site.

The gate always runs, even for documentation-only PRs. It never receives Cloudflare
credentials or deploys the site. Local hooks alone can be bypassed; the required
GitHub check is the merge gate. Secret scanning and push protection are also enabled.

### Local checks

Install Python 3, Go, the current Node.js LTS, ShellCheck, and pre-commit
(`pip install -r .github/ci-requirements.txt`). Pre-commit installs the pinned
actionlint, zizmor, check-jsonschema, and Gitleaks tools automatically.

```sh
pre-commit install --install-hooks
pre-commit run --all-files
pre-commit run gitleaks-files --hook-stage manual --all-files
pre-commit run gitleaks-history --hook-stage manual --all-files
git diff --check
```

Normal commits scan staged changes for secrets; the manual commands also check
uncommitted files and history. TLS tests mock network calls. Offline zizmor does
not audit upstream dependencies; passing checks is not a security guarantee.

## Deployment configuration

Configure **Settings -> Secrets and variables -> Actions** and
**Settings -> Environments -> github-pages**:

| Kind | Name | Purpose |
|---|---|---|
| Variable | `SITE_DOMAIN` | Canonical hostname, currently `mrinmaydhar.com`; no scheme, port, or path |
| Variable | `CLOUDFLARE_ZONE_ID` | Cloudflare zone used for DNS checks and cache purging |
| `github-pages` environment secret | `CLOUDFLARE_API_TOKEN` | Zone-scoped **DNS Read**, **DNS Edit**, and **Cache Purge** |

Keep the Cloudflare token out of repository secrets: workflows on Renovate (and
other same-repository) branches can read repository secrets, while the
`github-pages` environment only allows `main`.

`SITE_DOMAIN` must match **Settings -> Pages -> Custom domain**. Changing the
variable does not change Pages, DNS, or static Open Graph URLs. Publishing uses an
Actions artifact, not a CNAME file.

Keep apex and `www` CNAME records pointing to `<repository-owner>.github.io`, with
Cloudflare proxying enabled. Use **Full (strict)** SSL/TLS and Pages **Enforce HTTPS**.

### When workflows run

| Workflow | Trigger |
|---|---|
| [CI Gate](.github/workflows/checks.yml) | PR to `main`, or manual |
| [Deploy Site](.github/workflows/deploy.yml) | Push to `main` changing `web/**`, `resume/**`, or the build/deploy workflows; or manual |
| [Monitor TLS Certificates](.github/workflows/monitor-tls-cert.yml) | Daily at 03:17 UTC, or manual |
| [Recover TLS Certificate](.github/workflows/recover-tls-cert.yml) | After a failed TLS monitor on `main`, or manual |

Deployment publishes the complete site, then purges Cloudflare's cache and checks
DNS. Run manual deployments from `main`; other branches cannot use `github-pages`.
Documentation/TLS-monitor-only changes do not redeploy or purge the CDN.

The PDF cache hashes resume inputs and the build workflow, excluding the HTML
viewer and generated PDF. Website/viewer changes reuse the PDF; changed inputs or
a missing/evicted cache trigger compilation. Missing/empty PDFs fail the build.
PR caches are scoped to the PR, so `main` recompiles once after merging resume
changes. Delete the matching Actions cache to force recompilation.

## Dependency updates

CI uses the latest Python 3 and Node.js LTS (`3.x` and `lts/*` with
`check-latest`), so runtime versions need no maintenance. New runtime releases take
effect on the next run, without a PR or waiting period.

Actions and pre-commit hooks are pinned to commit SHAs with exact version comments
(`# v6.1.0`, and `# frozen: v8.30.1` for hooks). The Mend Renovate app runs
[Renovate](.github/renovate.json) about every 4 hours and updates those pins plus
[ci-requirements.txt](.github/ci-requirements.txt):

- Updates wait 7 days after release; fixes for GitHub security alerts skip the wait.
- Minor/patch updates share one PR. Renovate merges it itself, only when the
  Pre-merge Quality Gate passed, the branch is up to date with `main`, and no one
  else pushed to it. It rebases the PR when `main` moves; the ruleset is never bypassed.
- Major updates and digest-only changes (a moved release tag) get separate PRs
  for manual review.
- Renovate's merges trigger Deploy Site when they change the build/deploy workflows.
- The **Dependency Dashboard** issue lists updates waiting out the 7 days, major
  updates awaiting review, and lookup or config errors.

The literal `v4` in `api.cloudflare.com/client/v4` is the Cloudflare REST API
contract, not a pinned package or Action. Renovate cannot safely translate it to a
future major API. The pinned GitHub Actions are updater-managed; Cloudflare request
shape and DNS safety are covered by tests instead. Adding the Cloudflare SDK would
add an install, lockfile, and update surface for only two read/patch operations.

Limitations:

- GitHub raises no security alerts for SHA-pinned Actions or hooks, so their fixes
  arrive as normal updates after 7 days. The pre-commit package gets security PRs.
- Age, tests, and builds reduce risk but do not prove an update is safe.

Setup: install the Mend Renovate GitHub App for this repository only. With
`.github/renovate.json` on `main`, Renovate skips its onboarding PR. Job logs are
in the Mend Developer Portal. Dependabot alerts stay enabled because Renovate reads
them; Dependabot security updates are off to avoid duplicate PRs.

## TLS monitoring and recovery

The monitor is **read-only**; it does not renew certificates, reset domains, change
DNS, or lower Cloudflare security. It checks Pages certificate state, expiry within
21 days, public HTTPS, `www` redirects, and each discovered GitHub Pages IPv4 origin.
Origin addresses come from `<repository-owner>.github.io`, never the proxied custom
domain. Logs report HTTP status and curl exit status separately.

Cloudflare **526** means origin-certificate validation failed. Switching to **Full**
hides that problem; retain **Full (strict)** and repair the origin certificate.

When the monitor fails on `main`, it calls the recovery workflow automatically.
The recovery first rechecks Pages and the origin certificate; an unrelated WAF,
HTTP, DNS, or monitor failure ends without writes. It resets the custom domain only
when Pages reports an expired certificate or `bad_authz`, or direct TLS verification
reports a certificate error. The workflow then:

1. Requires the configured Pages domain to be verified, HTTPS-enforced, and unchanged.
2. Requires both Cloudflare CNAMEs to point to `<repository-owner>.github.io`
   before changing anything. It builds an allowlist from exactly those two record
   IDs; unrelated records are never eligible. Cloudflare requests are limited to
   list operations and a `PATCH` whose only field is the existing record's
   `proxied` flag. The workflow never creates or deletes DNS records.
3. Temporarily makes the CNAMEs DNS-only and waits for public DNS to reach Pages.
4. Removes and immediately restores the Pages hostname, then waits up to an hour
   for a certificate covering apex and `www`.
5. Verifies both hostnames directly against every Pages origin without `--insecure`.
6. Restores each record's original proxy state, including on failure, and verifies
   that Cloudflare no longer returns 526.

The TLS monitor runs at most daily, and overlapping monitor/recovery runs queue so
they cannot reset ACME state concurrently. A manual `Recover TLS Certificate` run on
`main` requires the confirmation value `RECOVER` and still runs the same checks. The
recovery never changes Cloudflare's SSL mode, and any failed rollback leaves the
workflow failed rather than silently succeeding.

If recovery keeps failing, inspect its summary and
[GitHub's provisioning guidance](https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https#troubleshooting-certificate-provisioning-certificate-not-yet-created-error)
before manually retrying. Verify the domain-verification TXT record, remove
conflicting A/AAAA records, and allow `letsencrypt.org` in any CAA policy. Repeated
failures need escalation to GitHub Support or a move away from GitHub Pages.
