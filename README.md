# Ahlyx Labs

Open-source security tools, systems work, and independent research.

- Website: https://ahlyxlabs.com
- API: https://api.ahlyxlabs.com
- Source and releases: https://github.com/Ahlyx
- Security and trust information: https://ahlyxlabs.com/security

## Architecture

```text
Internet
   |
Cloudflare proxy / DNS
   |
   +--> ahlyxlabs.com      -> Vercel frontend
   |
   +--> api.ahlyxlabs.com  -> Render Go backend
```

The backend is a single Go binary using chi, an in-memory TTL cache, bounded
rate limiters, and optional aggregate PostgreSQL telemetry. The public frontend
is static HTML, CSS, and vanilla JavaScript. Cloudflare provides the public
edge, Vercel serves the frontend, and Render hosts the Go API.

When configured, the backend requires a Cloudflare-added origin-verification
header for API and relay traffic. This protects the origin even if its provider
address is known. The secret itself is never stored in source; see
[`MANUAL_SECURITY_ACTIONS.md`](MANUAL_SECURITY_ACTIONS.md).

## Tools

### Security Enrichment

Enriches IP addresses, domains, URLs, and file hashes using relevant public and
commercial security sources. URL enrichment accepts sensitive input only as a
JSON request body; do not submit passwords, API keys, private invitation/reset
links, or other secrets to any public threat-intelligence lookup.

| Endpoint | Description |
|---|---|
| `GET /api/v1/ip/{address}` | IP reputation and contextual enrichment |
| `GET /api/v1/domain/{name}` | DNS, WHOIS, TLS, OTX, and reputation enrichment |
| `POST /api/v1/url` | URL enrichment with `{"url":"https://example.com","submit_urlscan":false}` |
| `GET /api/v1/hash/{hash}` | Hash reputation and malware metadata |

The legacy `GET /api/v1/url?...` route intentionally returns `410 Gone` rather
than process a full URL in a request query string.

Sources are selected by indicator type and include AbuseIPDB, VirusTotal,
IPinfo, AlienVault OTX, Google Safe Browsing, MalwareBazaar, CIRCL HashLookup,
DNS, WHOIS, TLS, and URLScan. URLScan active submission is optional and
requires both an operator setting and visitor opt-in.

### Network Scanner

The scanner preserves its OT/ICS port reference and is available for local or
explicitly isolated owner-controlled lab use. Hosted scanning is disabled in
normal production: `/api/v1/scanner/scan` is **not** a normal public production
endpoint. Controlled mode requires an explicit enablement flag and fixed
private CIDR allowlist.

### Hardware Dashboard

Shows aggregate telemetry from the Ahlyx Labs cloud backend: runtime platform,
uptime, CPU utilization/core count, memory utilization, disk capacity/I-O, and
aggregate network traffic. It does not display a visitor's machine or expose
hostnames, interface inventories, addresses, mount paths, or filesystem layout.

### PCAP Agent

[`pcap-agent`](https://github.com/Ahlyx/pcap-agent) analyzes traffic locally.
In local mode, the browser connects directly to `ws://localhost:7777/ws`; packet
analysis metadata does not transit Ahlyx Labs. Optional relay mode uses a
short-lived session with separate agent and viewer credentials: the agent uses
an authorization header and the viewer uses a WebSocket subprotocol. Raw packet
payloads are not relayed.

## Safe defaults

```text
SERVER_SCANNER_ENABLED=false
URLSCAN_ACTIVE_SUBMISSION=false
URLSCAN_VISIBILITY=unlisted
```

Missing enablement flags are false. Never enable the scanner on the normal
public backend. URLScan has no active submission unless the operator enables it
and the visitor explicitly asks for it.

## Local development

```bash
git clone https://github.com/Ahlyx/Ahlyx-Labs.git
cd Ahlyx-Labs
cp .env.example .env
go test ./...
go run ./cmd/server
```

For a static frontend preview:

```bash
python -m http.server 4173 --directory frontend
```

Open `http://localhost:4173/`. Local development does not require the
Cloudflare origin secret. Production configuration and verification steps are
documented in [`MANUAL_SECURITY_ACTIONS.md`](MANUAL_SECURITY_ACTIONS.md).

## Verification

```bash
go test ./...
go vet ./...
node tests/pcap/app.protocol.test.js
node tests/enrichment/privacy.test.js
node --test tests/site/static-site.test.js
```

## License

MIT
