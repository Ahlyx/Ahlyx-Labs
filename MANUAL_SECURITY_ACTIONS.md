# Manual security actions

This repository contains the application-side controls. The following dashboard
and account changes require the owner and must not be committed to source.

## Cloudflare-to-Render origin verification

`api.ahlyxlabs.com` is intentionally Cloudflare-proxied. Configure an
edge-to-origin verification secret before relying on this boundary in
production:

1. Generate a strong random secret in a password manager or trusted secret
   generator. Do not store it in this repository, issues, screenshots, or chat
   logs.
2. In **Cloudflare Dashboard → Rules → Transform Rules → Request Header
   Transform Rule**, create a rule matching hostname `api.ahlyxlabs.com`.
3. Set the static request header `X-Ahlyx-Origin-Verify` to that secret.
4. In the Render `ahlyx-labs` service, add the same value as
   `CLOUDFLARE_ORIGIN_SECRET` and deploy after the Cloudflare rule is active.
5. Verify a request through `https://api.ahlyxlabs.com` works, a request sent
   directly to the known Render origin without the header receives a generic
   `403`, and `/health` continues to work for the intended health-check path.
6. Confirm rate-limit behavior through the proxied custom API hostname. The
   application accepts `CF-Connecting-IP` only after this origin verification
   succeeds.

Local development intentionally works when `CLOUDFLARE_ORIGIN_SECRET` is not
set. Never add a sample secret to `.env.example`.

## Safe-default feature flags

These settings are already false when absent, but may be set explicitly in
Render for operational clarity:

```text
SERVER_SCANNER_ENABLED=false
URLSCAN_ACTIVE_SUBMISSION=false
URLSCAN_VISIBILITY=unlisted
```

The scanner must remain disabled on the normal public backend. URLScan active
submission requires both operator enablement and a visitor opt-in.

## Email, identity, and anti-impersonation

- Monitor SPF, DKIM, and DMARC alignment before moving DMARC toward
  quarantine/reject enforcement. Inventory every legitimate sender first.
- Review DNS for stale DKIM selectors and remove only selectors that no active
  sender uses.
- Keep a private administrator/recovery identity separate from public contact
  addresses.
- Use passkeys or hardware security keys for the domain registrar, Cloudflare,
  Render, Vercel, GitHub, and email provider. Review registrar lock, DNSSEC,
  and CAA settings where supported.

## GitHub protections

For `Ahlyx-Labs/master` and `pcap-agent/main`, require pull requests and CI
checks, prevent force pushes and deletion, require conversation resolution if
available, and require secure 2FA/passkeys for organization members.
