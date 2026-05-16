# Deployment Setup

## GitHub Secrets & Variables

Go to **repo Settings → Secrets and variables → Actions**

### Secret: `CLOUDFLARE_API_TOKEN`
- ✅ Already added
- Current permissions: **Edit zone DNS**, **DNS Read**
- **Needs additional permission:** `Zone → Cache Purge → Purge`
- To update: Cloudflare Dashboard → My Profile → API Tokens → edit the token → add permission

### Variable: `CLOUDFLARE_ZONE_ID`
- ⬜ Needs real value (currently placeholder)
- Go to **Cloudflare Dashboard → mrinmaydhar.com → Overview** → right sidebar → copy **Zone ID**
- Set it under **Variables** tab (not Secrets) in GitHub repo settings

## Cloudflare API Token Permissions

The token needs these permissions (all scoped to zone `mrinmaydhar.com`):

| Permission | Required for |
|---|---|
| Zone → DNS → Edit | DNS record updates |
| Zone → Cache Purge → Purge | Flushing CDN cache after deploy |

## Cloudflare DNS

Ensure these DNS records exist in Cloudflare for `mrinmaydhar.com`:

| Type | Name | Content | Proxy |
|---|---|---|---|
| CNAME | `@` | `mrinmaydhar.github.io` | Proxied (orange cloud) |

## TLS Certificate + Cloudflare Proxy

GitHub Pages uses Let's Encrypt to provision TLS certs via HTTP-01 challenge.
When Cloudflare proxy (orange cloud) is enabled, cert provisioning can fail with a **526 error** because Cloudflare can't connect to the origin over HTTPS before a cert exists.

**If you see a 526 error or cert provisioning failure:**

Run the **"Fix TLS Certificate Provisioning"** workflow from Actions tab (`workflow_dispatch`). It will:
1. Temporarily disable Cloudflare proxy (DNS only / grey cloud)
2. Wait for GitHub Pages to provision the cert (up to 10 min)
3. Re-enable the proxy

**Manual fix (if the Action fails):**
1. Cloudflare Dashboard → DNS → set `mrinmaydhar.com` and `www` records to "DNS only" (grey cloud)
2. GitHub repo Settings → Pages → remove custom domain, save, re-add `mrinmaydhar.com`, save
3. Wait for "Enforce HTTPS" to show cert is active
4. Cloudflare Dashboard → DNS → set records back to "Proxied" (orange cloud)

**SSL/TLS mode:** Set to **Full** in Cloudflare Dashboard → SSL/TLS → Overview.

## After Setup

1. Update the secret and variable with real values
2. Commit and push the code changes
3. The workflow will auto-deploy and purge Cloudflare cache
4. Verify `mrinmaydhar.com` shows the landing page
5. Verify `mrinmaydhar.com/resume` shows the resume PDF
