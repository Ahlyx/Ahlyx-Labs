# Ahlyx Labs

> Unified security tools platform — one binary, one deployment, one brand.

**Live:** [ahlyxlabs.com](https://ahlyxlabs.com) · **API:** [api.ahlyxlabs.com](https://api.ahlyxlabs.com)

---

## Overview

Ahlyx Labs consolidates three security tools into a single monorepo: a multi-source **Security Enrichment API**, a TCP **Network Scanner** with OT/ICS port awareness, and a real-time **Hardware Dashboard**. A single Go binary on [Render](https://render.com) serves all backend routes; a Vercel deployment serves all frontends as static files under the `ahlyxlabs.com` domain.

---

## Tools

### Security Enrichment API
Aggregates threat intelligence from multiple sources against IPs, domains, URLs, and file hashes. Each query fans out to all relevant sources concurrently, merges results, and caches responses with a TTL that degrades gracefully on partial failures.

| Endpoint | Description |
|---|---|
| `GET /api/v1/ip/{address}` | IP geolocation, abuse score, VirusTotal, bogon/Tor detection |
| `GET /api/v1/domain/{name}` | WHOIS, DNS records, SSL, VirusTotal, OTX |
| `GET /api/v1/url?url=` | Google Safe Browsing, URLScan, VirusTotal |
| `GET /api/v1/hash/{hash}` | VirusTotal, MalwareBazaar, CIRCL HashLookup |

**Intel sources:** AbuseIPDB · VirusTotal · IPinfo · AlienVault OTX · Google Safe Browsing · URLScan · MalwareBazaar · CIRCL HashLookup · WHOIS · DNS · SSL

### Network Scanner
TCP port scanner with a curated OT/ICS port map alongside common service ports. Accepts a subnet or single host as input.

| Endpoint | Description |
|---|---|
| `GET /api/v1/scanner/scan?subnet=` | Scan a subnet or host for open ports |

### Hardware Dashboard
Real-time system telemetry for the host running the backend.

| Endpoint | Description |
|---|---|
| `GET /api/v1/hardware/system` | OS, hostname, uptime, platform |
| `GET /api/v1/hardware/cpu` | Model, core count, usage per core |
| `GET /api/v1/hardware/ram` | Total, used, available, swap |
| `GET /api/v1/hardware/disk` | Per-partition usage |
| `GET /api/v1/hardware/network` | Bytes sent/received per interface |

### Health Check
```
GET /health → 200 OK  {"status":"ok"}
```

---

## Architecture

```
Ahlyx-Labs/
├── cmd/server/main.go          ← single entrypoint, registers all route groups
├── internal/
│   ├── shared/                 ← cache, config, middleware, rate limiter, response helpers
│   ├── enrichment/             ← handlers, services (one file per source), models, validators
│   ├── scanner/                ← TCP scanner logic, OT/ICS port map, handler
│   └── hardware/               ← system telemetry handler and models
└── frontend/
    ├── landing/
    ├── enrichment/
    ├── scanner/
    ├── hardware/
    └── vercel.json
```

**Backend:** Go 1.22 · [chi](https://github.com/go-chi/chi) router · per-IP token-bucket rate limiting (`golang.org/x/time/rate`) · in-memory TTL cache (`sync.RWMutex`) · Dockerized for Render

**Frontend:** Vanilla JS / HTML / CSS · dark terminal design language · Vercel Analytics + Speed Insights · GA4 (G-99NT7YXMY8) · consent banner on all pages

**Infrastructure:** Render (backend) · Vercel (frontend) · Cloudflare (DNS, proxy)

---

## Rate Limits

| Route group | Limit |
|---|---|
| `/api/v1/ip`, `/api/v1/domain`, `/api/v1/hash` | 30 req / min per IP |
| `/api/v1/url` | 10 req / min per IP |
| `/api/v1/scanner/scan` | 5 req / min per IP |
| `/api/v1/hardware/*` | 30 req / min per IP |

---

## Caching

Responses are cached in memory with TTL tiers based on source reliability:

| Condition | TTL |
|---|---|
| All sources succeeded | 1 hour |
| Any source failed | 15 minutes |
| All sources failed | Not cached |

---

## Environment Variables

API keys are set in the Render dashboard and are **not committed to the repo**. See `.env.example` for the full list.

| Variable | Used by |
|---|---|
| `ABUSEIPDB_API_KEY` | Enrichment — IP |
| `VIRUSTOTAL_API_KEY` | Enrichment — IP, domain, URL, hash |
| `IPINFO_API_KEY` | Enrichment — IP |
| `OTX_API_KEY` | Enrichment — domain |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Enrichment — URL |
| `URLSCAN_API_KEY` | Enrichment — URL |
| `MALWAREBAZAAR_API_KEY` | Enrichment — hash |
| `PORT` | Server listen port (default: `8080`) |
| `CACHE_TTL_SECONDS` | Override full-success TTL (default: `3600`) |

---

## Local Development

### Prerequisites
- Go 1.22+
- Docker (optional, for container builds)

### Run locally

```bash
git clone https://github.com/Ahlyx/Ahlyx-Labs.git
cd Ahlyx-Labs
cp .env.example .env
# fill in API keys in .env
go run ./cmd/server
```

Server starts on `http://localhost:8080`. Open any `frontend/*/index.html` directly in a browser or serve the `frontend/` directory with a static server.

### Docker

```bash
docker build -t ahlyx-labs .
docker run --env-file .env -p 8080:8080 ahlyx-labs
```

---

## Deployment

### Backend → Render

1. **New → Web Service** → connect `Ahlyx/Ahlyx-Labs`
2. Environment: **Docker** · Branch: `main` · Root directory: *(leave empty)*
3. Add all 7 API keys as environment variables in the Render dashboard
4. Deploy → note the service URL (e.g. `ahlyx-labs.onrender.com`)
5. Verify: `curl https://ahlyx-labs.onrender.com/health`

### Frontend → Vercel

1. **New Project** → import `Ahlyx/Ahlyx-Labs`
2. Root directory: `frontend` · Framework preset: **Other** · Build command: *(empty)* · Output directory: `./`
3. Deploy → note the Vercel URL

### DNS → Cloudflare

**Frontend (apex + www → Vercel):**
```
CNAME  @    →  <vercel-cname-target>   (proxy ON)
CNAME  www  →  <vercel-cname-target>   (proxy ON)
```

**API subdomain → Render:**
```
CNAME  api  →  ahlyx-labs.onrender.com   (proxy ON)
```
Then in Render: **Settings → Custom Domains → add** `api.ahlyxlabs.com`

### Verification

```bash
curl https://api.ahlyxlabs.com/health
curl "https://api.ahlyxlabs.com/api/v1/ip/8.8.8.8"
# Open https://ahlyxlabs.com in a browser
# Check GA4 Realtime report for your visit
```

---

## Module

```
github.com/Ahlyx/Ahlyx-Labs
```

---

## License

MIT
