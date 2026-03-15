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
**Database:** Neon PostgreSQL (free tier, AWS US West 2) — query logging only
```
Ahlyx-Labs/
├── cmd/server/main.go          ← single entrypoint, registers all route groups
├── internal/
│   ├── shared/                 ← cache, config, db, middleware, rate limiter, response helpers
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
- All API keys and DATABASE_URL set as environment variables in Render dashboard (not in repo)

### Frontend — Vercel
- Project: `ahlyx-labs`
- Root directory: `frontend`
- Framework preset: Other
- Build command: *(empty)*
- Output directory: `./`
- Custom domain: `ahlyxlabs.com` + `www.ahlyxlabs.com`

### Database — Neon
- Project: `Ahlyx-labs`
- Region: AWS US West 2 (Oregon)
- PostgreSQL 16
- Connection string stored as `DATABASE_URL` in Render environment variables
- Table: `query_logs` — created automatically on first boot via `shared.InitDB()`
- Schema:
```sql
CREATE TABLE IF NOT EXISTS query_logs (
    id           BIGSERIAL PRIMARY KEY,
    tool         TEXT NOT NULL,
    query_type   TEXT,
    verdict      TEXT,
    threat       BOOLEAN,
    source_count INTEGER,
    response_ms  INTEGER,
    host_count   INTEGER,
    port_count   INTEGER,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
```

### DNS — Cloudflare
```
A      @    →  216.198.79.1                        (proxy ON)
CNAME  www  →  990da1196320c862.vercel-dns-017.com  (proxy ON)
CNAME  api  →  ahlyx-labs.onrender.com              (proxy ON)
```

---

## Current Tools

### Security Enrichment API (`/enrichment`)
Aggregates threat intelligence from 8 sources against IPs, domains, URLs, and file hashes. Each query fans out concurrently, merges results, and caches with TTL tiers.

- **Frontend:** `frontend/enrichment/` — tabs for IP/Domain/URL/Hash, recent queries history, verdict banner, feedback widget
- **Backend:** `internal/enrichment/` — handlers, services (one file per source), models, validators
- **Sources:** AbuseIPDB · VirusTotal · IPinfo · AlienVault OTX · Google Safe Browsing · URLScan · MalwareBazaar · CIRCL HashLookup · WHOIS · DNS · SSL
- **Routes:**
```
GET /api/v1/ip/{address}
GET /api/v1/domain/{name}
GET /api/v1/url?url=
GET /api/v1/hash/{hash}
```
- **Rate limits:** 30 req/min (IP/domain/hash), 10 req/min (URL)
- **Caching:** 1hr full success, 15min partial, no cache on total failure
- **Logging:** logs tool, query_type, verdict, threat, source_count, response_ms

### Network Scanner (`/scanner`)
TCP port scanner with curated OT/ICS port map. Two-column layout — OT/ICS reference table on left, scan interface on right. Accepts IP or CIDR up to /24.

- **Frontend:** `frontend/scanner/` — OT sidebar always expanded, preset buttons, results table with OT flag highlighting
- **Backend:** `internal/scanner/` — TCP dial with 500ms timeout, worker pool of 50, /24 hard limit
- **OT/ICS ports:** Modbus (502), S7comm (102), EtherNet/IP (44818/2222), OPC-UA (4840), DNP3 (20000), BACnet (47808), OMRON FINS (9600), PCWorx (1962), GE SRTP (18245), Emerson DeltaV (4000), Foundation Fieldbus (1089/1090/1091)
- **Common ports:** FTP, SSH, Telnet, HTTP, HTTPS, RDP, MySQL, PostgreSQL, Redis, MongoDB, and more
- **Route:** `GET /api/v1/scanner/scan?subnet=`
- **Rate limit:** 5 req/min
- **No caching** — results are always live
- **Logging:** logs tool, query_type (tcp), host_count, port_count, response_ms

### Hardware Dashboard (`/hardware`)
Real-time system telemetry for the Render backend host. Polls every 10 seconds with staggered 200ms fetches per panel to stay within rate limits.

- **Frontend:** `frontend/hardware/` — hero section, SYSTEM/CPU/RAM/DISK/NETWORK cards, live timestamp
- **Backend:** `internal/hardware/` — uses gopsutil/v3 for all system metrics
- **Routes:**
```
GET /api/v1/hardware/system
GET /api/v1/hardware/cpu
GET /api/v1/hardware/ram
GET /api/v1/hardware/disk
GET /api/v1/hardware/network
```
- **Rate limit:** 30 req/min
- **Note:** Reports Render VM metrics (AMD EPYC 7R13, Linux) — expected behavior, not a bug
- **Logging:** logs hardware_dashboard_loaded event via GA4 only (no DB logging — telemetry not query-based)

### Baptisia (external link)
Safety-enforcing DSL compiler for ICS/OT systems, compiles `.ba` source files to C. Lives at `github.com/Ahlyx/Baptisia` — linked from landing page only, no backend or frontend in this repo.

---

## API Routes
```
GET  /health                          → {"status":"ok"}
GET  /api/v1/ip/{address}             → IP enrichment
GET  /api/v1/domain/{name}            → Domain enrichment
GET  /api/v1/url?url=                 → URL enrichment
GET  /api/v1/hash/{hash}              → Hash enrichment
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
| `DATABASE_URL` | Neon PostgreSQL connection string |
| `PORT` | Server listen port (default: `8080`) |
| `CACHE_TTL_SECONDS` | Full-success TTL override (default: `3600`) |

---

## Frontend Design System

All frontends share these CSS variables and fonts:
```css
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600&display=swap');

:root {
    --bg: #0a0e1a;
    --bg-panel: #0d1321;
    --bg-elevated: #111827;
    --border: #1a2a4a;
    --border-accent: #005f6b;
    --accent: #00e5ff;
    --accent-dim: rgba(0, 229, 229, 0.08);
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

**Every page must have:**
- Sticky header with `[ ← BACK ]` link, tool name, subtitle
- Hero section with large cyan heading (`clamp(2rem, 5vw, 3.5rem)`, `font-weight: 800`, `color: var(--accent)`)
- Inline SVG favicon: `<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">`
- Consent banner with GA4 accept/decline (localStorage key: `analytics_consent`)
- Vercel Analytics + Speed Insights scripts
- GA4 script (`G-99NT7YXMY8`)
- Footer with `github.com/Ahlyx`, `@AhIyxx`, `Privacy Policy`
- `font-family: var(--font-mono)` on body

**Note:** `enrichment/style.css` uses slightly different variable names (`--text`, `--text-dim`, `--text-muted`, `--bg-card`) that map to the same values. Do not rename them.

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

## Adding a New Tool

### If the tool has a backend (needs API endpoints):

1. Create `internal/<toolname>/` with handlers, models, and any service files
2. Register routes in `cmd/server/main.go` following the existing pattern:
```go
toolRL := shared.NewRateLimiter(rate.Every(Xs), burst)
r.With(toolRL.Middleware).Get("/api/v1/<toolname>/...", toolhandlers.Handle...)
```
3. Add `shared.LogQuery("toolname", ...)` call in each handler after the response is built
4. Add any required API keys to Render environment variables and `.env.example`
5. Create `frontend/<toolname>/` with `index.html`, `app.js`, `style.css`
6. Add rewrites to `frontend/vercel.json`:
```json
{ "source": "/<toolname>/(.*)", "destination": "/<toolname>/index.html" },
{ "source": "/<toolname>",      "destination": "/<toolname>/index.html" }
```
7. Add a card to `frontend/landing/index.html`
8. Add the URL to `frontend/sitemap.xml`
9. Submit the new URL in Google Search Console → Sitemaps

### If the tool is frontend-only (no backend):

Steps 1-4 are skipped. Start at step 5.

### Standardization checklist for any new frontend:

- [ ] CSS variables match design system exactly
- [ ] `font-family: var(--font-mono)` on body
- [ ] Hero heading: `clamp(2rem, 5vw, 3.5rem)`, `font-weight: 800`, `color: var(--accent)`
- [ ] Sticky header with back link, tool name, subtitle
- [ ] Inline SVG favicon present
- [ ] Consent banner wired to `analytics_consent` localStorage key
- [ ] GA4 script present with correct measurement ID
- [ ] Vercel Analytics + Speed Insights scripts present
- [ ] Footer with github/twitter/privacy links
- [ ] API base URL points to `https://api.ahlyxlabs.com`
- [ ] GA4 events added for submit, result, error, feedback (where applicable)
- [ ] `shared.LogQuery` called in backend handler

### Integration prompt template for Claude Code:
```
You are integrating a new tool into the Ahlyx-Labs monorepo.
Read CLAUDE.md first for full platform context before making any changes.

Tool name: <name>
Description: <one line>
Has backend: yes/no
API keys needed: <list or none>

Files from the standalone repo are attached. Integrate this tool following
the patterns in CLAUDE.md exactly — same rate limiting approach, same
logging pattern, same frontend design system, same GA4 event structure.
Add a card to the landing page and the URL to sitemap.xml.
Run go build ./... at the end to verify the backend compiles.
Print a summary of every file created or modified.
```

---

## Rules

- All Go code lives in `internal/` — no business logic in `cmd/`
- All frontend code lives in `frontend/` — one subfolder per tool
- `shared/` is used by all tools — no tool-specific code goes there
- Do NOT use `innerHTML` to insert user-supplied data — use `textContent` or `createElement`
- Do NOT modify `.env` files
- Maintain JSON response parity with existing enrichment API schemas (pointer types for optional fields)
- Scanner `/24` hard limit is a security control — do not remove it
- CORS is locked to `ahlyxlabs.com` and `www.ahlyxlabs.com` — do not revert to `*`
- API base URL in all frontend JS is `https://api.ahlyxlabs.com` — do not revert to `onrender.com`
- Favicon is an inline SVG data URI on all `index.html` files
- Never log IP addresses, domain names, URLs, or hash values to the database
- `DATABASE_URL` not set = app starts normally with DB logging silently disabled
- All `LogQuery` calls run in goroutines and never block HTTP responses