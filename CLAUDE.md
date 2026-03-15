# CLAUDE.md

## Project
Ahlyx Labs — unified security tools platform. Single Go binary + multi-frontend static site.

**Live:** https://ahlyxlabs.com  
**API:** https://api.ahlyxlabs.com  
**Repo:** https://github.com/Ahlyx/Ahlyx-Labs

---

## Commands
```bash
# Run backend
go run ./cmd/server

# Build binary
go build -ldflags="-s -w" -o ahlyx-labs ./cmd/server

# Run tests
go test ./...

# Build Docker image
docker build -t ahlyx-labs .

# Run with env file
docker run --env-file .env -p 8080:8080 ahlyx-labs
```

---

## Architecture

**Backend:** Go 1.25 · chi router · single binary · Dockerized · deployed on Render  
**Frontend:** Vanilla JS/HTML/CSS · no build step · deployed on Vercel  
**DNS/Proxy:** Cloudflare (proxy ON for all records)  
**Analytics:** GA4 (G-99NT7YXMY8) + Vercel Analytics + Speed Insights
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
    ├── robots.txt
    ├── sitemap.xml
    └── vercel.json
```

---

## Infrastructure

### Backend — Render
- Service: `ahlyx-labs` (Docker, Web Service)
- Custom domain: `api.ahlyxlabs.com`
- Branch: `master`
- Root directory: *(empty — Dockerfile is in repo root)*
- All 7 API keys set as environment variables in Render dashboard (not in repo)

### Frontend — Vercel
- Project: `ahlyx-labs`
- Root directory: `frontend`
- Framework preset: Other
- Build command: *(empty)*
- Output directory: `./`
- Custom domain: `ahlyxlabs.com` + `www.ahlyxlabs.com`

### DNS — Cloudflare
```
A      @    →  216.198.79.1                        (proxy ON)
CNAME  www  →  990da1196320c862.vercel-dns-017.com  (proxy ON)
CNAME  api  →  ahlyx-labs.onrender.com              (proxy ON)
```

---

## API Routes
```
GET  /health                          → {"status":"ok"}
GET  /api/v1/ip/{address}             → IP enrichment (AbuseIPDB, IPinfo, VirusTotal)
GET  /api/v1/domain/{name}            → Domain enrichment (WHOIS, DNS, SSL, VT, OTX)
GET  /api/v1/url?url=                 → URL enrichment (SafeBrowsing, URLScan, VT)
GET  /api/v1/hash/{hash}              → Hash enrichment (VT, MalwareBazaar, CIRCL)
GET  /api/v1/scanner/scan?subnet=     → TCP port scan (IP or CIDR up to /24)
GET  /api/v1/hardware/system          → OS, hostname, processor
GET  /api/v1/hardware/cpu             → Cores, speed, usage
GET  /api/v1/hardware/ram             → Memory utilization
GET  /api/v1/hardware/disk            → Partition usage + I/O totals
GET  /api/v1/hardware/network         → Interface addresses + traffic totals
```

---

## Rate Limits

| Route group | Limit |
|---|---|
| `/api/v1/ip`, `/api/v1/domain`, `/api/v1/hash` | 30 req/min per IP |
| `/api/v1/url` | 10 req/min per IP |
| `/api/v1/scanner/scan` | 5 req/min per IP |
| `/api/v1/hardware/*` | 30 req/min per IP |

---

## Environment Variables

Set in Render dashboard — never committed to repo.

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
| `CACHE_TTL_SECONDS` | Full-success TTL override (default: `3600`) |

---

## Frontend Design System

All four frontends share these CSS variables:
```css
:root {
    --bg: #0a0e1a;
    --bg-panel: #0d1321;
    --bg-elevated: #111827;
    --border: #1a2a4a;
    --border-accent: #005f6b;
    --accent: #00e5ff;
    --accent-dim: rgba(0, 229, 255, 0.08);
    --threat: #ff4444;
    --threat-dim: rgba(255, 68, 68, 0.08);
    --white: #e0f7fa;
    --dim: #546e7a;
    --muted: #37474f;
    --font-mono: 'Share Tech Mono', monospace;
    --font-body: 'Exo 2', sans-serif;
    --glow: 0 0 10px rgba(0, 229, 255, 0.15);
}
```

**Note:** `enrichment/style.css` uses slightly different variable names (`--text`, `--text-dim`, `--text-muted`, `--bg-card`) that map to the same values. Do not rename them — the enrichment JS references them.

---

## GA4 Event Tracking

Measurement ID: `G-99NT7YXMY8`  
Consent system: GA4 initializes in denied mode, upgrades on `[ ACCEPT ]` click.  
All events guarded with `typeof gtag !== 'undefined'`.

| Event | Tool | Parameters |
|---|---|---|
| `enrichment_submitted` | enrichment | `query_type` |
| `enrichment_result` | enrichment | `query_type`, `source_count`, `has_threat` |
| `enrichment_error` | enrichment | `query_type` |
| `enrichment_feedback` | enrichment | `value` (up/down), `query_type` |
| `scan_submitted` | scanner | `input_type` (cidr/ip) |
| `scan_result` | scanner | `input_type`, `host_count`, `open_port_count` |
| `scan_error` | scanner | `input_type` |
| `scan_feedback` | scanner | `value` (up/down) |
| `hardware_dashboard_loaded` | hardware | *(none)* |
| `hardware_fetch_error` | hardware | `panel` |

---

## Rules

- All Go code lives in `internal/` — no business logic in `cmd/`
- All frontend code lives in `frontend/` — one subfolder per tool
- `shared/` is used by all three tools — no tool-specific code goes there
- Do NOT use `innerHTML` to insert user-supplied data — use `textContent` or `createElement`
- Do NOT modify `.env` files
- Maintain JSON response parity with existing enrichment API schemas (pointer types for optional fields)
- Scanner `/24` hard limit is a security control — do not remove it
- CORS is locked to `ahlyxlabs.com` and `www.ahlyxlabs.com` — do not revert to `*`
- API base URL in all frontend JS is `https://api.ahlyxlabs.com` — do not revert to `onrender.com`
- Favicon is an inline SVG data URI on all four `index.html` files