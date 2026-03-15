# Ahlyx Labs — Full Rewrite Spec
> The gitingest files are reference material for business logic only — do not copy code from them.
> Build everything from scratch using idiomatic Go and clean vanilla JS.

---

## Project Goal

Consolidate three existing security tools (Security Enrichment API, Network Scanner, Hardware Dashboard) plus one compiler project (Baptisia) into a single monorepo under the **Ahlyx Labs** brand.

- One Go binary on Render serves all backend API routes
- One Vercel deployment serves all frontends as static files
- Consistent dark-terminal design language across all frontends
- Each original repo stays on GitHub independently — this monorepo is the production platform

---

## Repository Structure

```
Ahlyx-Labs/
├── CLAUDE.md                        ← instructions for future Claude Code sessions
├── README.md
├── .env.example
├── go.mod                           ← module: github.com/Ahlyx/Ahlyx-Labs
├── go.sum
├── Dockerfile
│
├── cmd/
│   └── server/
│       └── main.go                  ← single entrypoint, registers all route groups
│
├── internal/
│   ├── shared/
│   │   ├── cache.go                 ← unified in-memory TTL cache (sync.RWMutex)
│   │   ├── ratelimit.go             ← per-IP token bucket (golang.org/x/time/rate)
│   │   ├── middleware.go            ← CORS, RealIP, Logger, Recoverer
│   │   ├── response.go              ← writeJSON / writeError helpers
│   │   └── config.go                ← reads all env vars for all tools
│   │
│   ├── enrichment/
│   │   ├── handlers/
│   │   │   ├── ip.go
│   │   │   ├── domain.go
│   │   │   ├── url.go
│   │   │   ├── hash.go
│   │   │   └── helpers.go
│   │   ├── services/
│   │   │   ├── client.go            ← shared HTTP client with timeout
│   │   │   ├── abuseipdb.go
│   │   │   ├── ipinfo.go
│   │   │   ├── virustotal.go
│   │   │   ├── otx.go
│   │   │   ├── safebrowsing.go
│   │   │   ├── urlscan.go
│   │   │   ├── malwarebazaar.go
│   │   │   ├── circl.go
│   │   │   ├── whois.go
│   │   │   ├── dns.go
│   │   │   └── ssl.go
│   │   ├── models/
│   │   │   └── models.go            ← all response structs with pointer types
│   │   └── validators/
│   │       └── validators.go        ← IP/domain/URL/hash validation + bogon check
│   │
│   ├── scanner/
│   │   ├── handlers/
│   │   │   └── scan.go
│   │   ├── scanner.go               ← TCP port scanning logic (net package)
│   │   ├── ports.go                 ← OT/ICS port map + common port map
│   │   └── models.go
│   │
│   └── hardware/
│       ├── handlers/
│       │   └── hardware.go
│       └── models.go
│
└── frontend/
    ├── landing/
    │   ├── index.html
    │   ├── app.js
    │   └── style.css
    ├── enrichment/
    │   ├── index.html
    │   ├── app.js
    │   └── style.css
    ├── scanner/
    │   ├── index.html
    │   ├── app.js
    │   └── style.css
    ├── hardware/
    │   ├── index.html
    │   ├── script.js
    │   └── style.css
    └── vercel.json
```

---

## Backend: Go Binary

### Module and Dependencies

```
module github.com/Ahlyx/ahlyx-labs

go 1.22
```

Required dependencies (same as existing enrichment scanner-go, extend as needed):
- `github.com/go-chi/chi/v5`
- `github.com/go-chi/cors`
- `github.com/joho/godotenv`
- `github.com/likexian/whois`
- `github.com/likexian/whois-parser`
- `golang.org/x/time`

### cmd/server/main.go

Register three route groups under one chi router:

```
/api/v1/ip/{address}        → enrichment.HandleIP
/api/v1/domain/{name}       → enrichment.HandleDomain
/api/v1/url                 → enrichment.HandleURL   (query param: ?url=...)
/api/v1/hash/{hash}         → enrichment.HandleHash
/api/v1/scanner/scan        → scanner.HandleScan     (query param: ?subnet=...)
/api/v1/hardware/system     → hardware.HandleSystem
/api/v1/hardware/cpu        → hardware.HandleCPU
/api/v1/hardware/ram        → hardware.HandleRAM
/api/v1/hardware/disk       → hardware.HandleDisk
/api/v1/hardware/network    → hardware.HandleNetwork
/health                     → 200 OK, {"status":"ok"}
```

Apply global middleware: `middleware.RealIP`, `middleware.Logger`, `middleware.Recoverer`, CORS (allow `*` for dev; tighten to Vercel domain in prod).

Apply per-route rate limiting injected via closure (same pattern as existing scanner-go):
- Enrichment IP/domain/hash: 30 req/min
- Enrichment URL: 10 req/min
- Scanner scan: 5 req/min
- Hardware endpoints: 30 req/min

### shared/cache.go

Unified cache used by all three tools. Same design as existing scanner-go cache:
- `sync.RWMutex` + `map[string]cacheEntry`
- Each entry has `data []byte`, `expiry time.Time`
- TTL tiers: full success = 1 hour, partial success = 15 min, no cache on total failure
- Background cleanup goroutine every 10 minutes
- Methods: `Get(key) ([]byte, bool)`, `Set(key, data, sources)`, `Delete(key)`
- `Set` determines TTL tier by inspecting the `sources []SourceMetadata` slice — if all sources failed, don't cache; if any failed, use 15 min; otherwise 1 hour

### shared/config.go

Single `Config` struct loaded once at startup. Reads all environment variables for all tools:

```go
type Config struct {
    Port                  string
    AbuseIPDBKey          string
    VirusTotalKey         string
    IPInfoKey             string
    OTXKey                string
    GoogleSafeBrowsingKey string
    URLScanKey            string
    CacheTTLSeconds       int
}
```

Hardware and scanner endpoints need no API keys.

### shared/ratelimit.go

Per-IP token bucket identical to the existing scanner-go implementation. Takes `rate.Limit` and burst int, returns middleware-compatible `http.Handler` wrapper. Honors `X-Forwarded-For` for Render's reverse proxy.

---

## Enrichment Package

### Business Logic Reference

The enrichment package is a **direct port** of the existing `scanner-go` implementation into the new module structure. All handler logic, service call patterns, goroutine/WaitGroup patterns, and JSON models are carried over exactly.

**Key patterns to preserve:**
- Each handler: validate → cache lookup → fire goroutines → merge → cache → return
- Pointer types on all optional fields in models (produces `null` not omitted, matching existing behavior)
- Semaphore not required since the scanner-go didn't use one per-handler — WaitGroup + goroutines is sufficient
- `IsMalicious`/`IsKnownGood`/`IsBogon`/`IsTor` derived fields calculated the same way

### JSON Response Schemas

Preserve exactly. The existing enrichment frontend already works against these schemas.

**Base envelope (all responses):**
```json
{
  "query": "string",
  "query_type": "ip|domain|url|hash",
  "timestamp": "RFC3339",
  "sources": [{"source": "string", "success": bool, "error": "string|null"}]
}
```

**IP response adds:** `ip`, `geolocation`, `abuse`, `virustotal`, `is_bogon`, `is_tor`

**Domain response adds:** `domain`, `whois`, `dns`, `ssl`, `virustotal`, `otx`

**URL response adds:** `url`, `safe_browsing`, `urlscan`, `virustotal`, `is_malicious`

**Hash response adds:** `hash_value`, `hash_type`, `virustotal`, `malware_bazaar`, `circl`, `is_malicious`, `is_known_good`

Full struct definitions are in the existing `scanner-go/internal/models/models.go` — use those as the exact reference.

### Validators

Port directly from `scanner-go/internal/validators/validators.go`:
- `IsValidIP(s string) bool` — net.ParseIP
- `IsBogonIP(s string) bool` — RFC1918 + loopback + link-local + reserved ranges
- `IsValidDomain(s string) bool` — basic regex, no IP addresses
- `IsValidURL(s string) bool` — must start with http:// or https://
- `IsValidHash(s string) bool` + `DetectHashType(s string) string` — length-based MD5/SHA1/SHA256 detection

---

## Scanner Package

### Business Logic Reference

The original Python scanner uses Scapy for ARP host discovery. **Go cannot replicate raw ARP scanning without elevated privileges**, and Render's free tier runs as a non-root container. 

**Design decision:** The Go scanner performs TCP-only scanning (no ARP). The frontend will accept an IP or CIDR range and the backend will TCP-scan discovered/specified hosts. For local lab use the Python version with Scapy remains the right tool; the Go version is the hosted/remote-accessible version.

### Scan Logic (internal/scanner/scanner.go)

```
Input: subnet string (CIDR) or single IP
Validate: use net.ParseCIDR or net.ParseIP — reject invalid input
For CIDR: enumerate all host IPs in the range (skip network + broadcast)
  - Hard limit: reject subnets larger than /24 (max 254 hosts) to prevent abuse
For each IP: scan ports concurrently using goroutine pool (worker pool of 50)
For each port: net.DialTimeout("tcp", ip:port, 500ms)
Return: list of hosts with open ports
```

### Port Maps (internal/scanner/ports.go)

OT/ICS ports (preserve exactly from Python version):
```
502   → Modbus
102   → S7comm (Siemens PLC)
20000 → DNP3
44818 → EtherNet/IP (Rockwell PLC)
47808 → BACnet
4840  → OPC-UA
1962  → PCWorx (Phoenix Contact)
2222  → EtherNet/IP alt
9600  → OMRON FINS
```

Common ports to always scan:
```
21 → FTP
22 → SSH
23 → Telnet
80 → HTTP
443 → HTTPS
8080 → HTTP-Alt
8443 → HTTPS-Alt
+ all OT ports above
```

### JSON Response Schema

```json
{
  "subnet": "192.168.1.0/24",
  "hosts_found": 2,
  "scan_type": "tcp",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": null,
      "ports": [
        {
          "port": 502,
          "service": "Modbus",
          "ot_flag": true
        }
      ]
    }
  ]
}
```

Note: `mac` is always `null` in the Go version (no ARP). Include it in the schema for frontend compatibility.

### Handler (internal/scanner/handlers/scan.go)

```
GET /api/v1/scanner/scan?subnet=192.168.1.0/24

Validate subnet (reject > /24, reject invalid CIDR)
Rate limit: 5/min per IP
No caching (scan results are live)
Return ScanResponse JSON
```

---

## Hardware Package

### Design Decision

The hardware dashboard reports system metrics of whatever machine is running the binary. On Render free tier, this means it reports Render's container metrics — not useful for the user's own machine.

**Approach:** Keep the hardware endpoints in the Go binary as-is. They serve two purposes:
1. Useful when running the binary locally (dev mode / lab environment)
2. Demonstrates the concept for the portfolio

Do NOT add a note to the frontend saying "this shows Render's server." Just keep it factual.

### Endpoints and Response Schemas

Preserve the exact field names and structure from the Python `api.py`. The hardware frontend (`script.js`) references these field names directly.

**GET /api/v1/hardware/system**
```json
{
  "os": "Linux",
  "os_version": "...",
  "architecture": "64bit",
  "hostname": "...",
  "processor": "..."
}
```

**GET /api/v1/hardware/cpu**
```json
{
  "physical_cores": 2,
  "total_cores": 4,
  "current_speed": "2400.00 MHz",
  "cpu_usage": "12.5%"
}
```

**GET /api/v1/hardware/ram**
```json
{
  "total": "8.00 GB",
  "used": "3.21 GB",
  "available": "4.79 GB",
  "usage": "40.1%",
  "swap_total": "2.00 GB",
  "swap_used": "0.00 GB",
  "swap_usage": "0.0%"
}
```

**GET /api/v1/hardware/disk**
```json
{
  "partitions": [
    {
      "mountpoint": "/",
      "filesystem": "ext4",
      "total": "20.00 GB",
      "used": "8.50 GB",
      "free": "11.50 GB",
      "usage": "42.5%"
    }
  ],
  "total_read": "1.23 GB",
  "total_written": "0.87 GB",
  "read_ops": "123456",
  "write_ops": "98765"
}
```

**GET /api/v1/hardware/network**
```json
{
  "interfaces": [
    {
      "interface": "eth0",
      "ip_address": "10.0.0.1",
      "subnet_mask": "255.255.255.0"
    }
  ],
  "bytes_sent": "45.23 MB",
  "bytes_received": "123.45 MB",
  "packets_sent": 54321,
  "packets_received": 98765
}
```

### Go Implementation Notes

Use the `github.com/shirou/gopsutil/v3` package — it's the Go equivalent of Python's `psutil`. Add it to go.mod.

```go
import (
    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/shirou/gopsutil/v3/disk"
    "github.com/shirou/gopsutil/v3/host"
    "github.com/shirou/gopsutil/v3/mem"
    "github.com/shirou/gopsutil/v3/net"
)
```

Format all byte values as strings matching the Python output: `"X.XX GB"`, `"X.XX MB"`, `"X.XX%"`.

---

## Frontend

### Design System

All frontends share these CSS variables and rules. Each frontend's stylesheet (or `<style>` block) should open with:

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

Google Fonts import at top of every stylesheet:
```css
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600&display=swap');
```

Rules:
- Dark background (`--bg`), cyan accent (`--accent`), red for threats (`--threat`)
- Monospace font for labels, data values, and headers
- No rounded corners > 4px
- Hover states use border-color transition to `--accent`
- All user-facing text uses `textContent` not `innerHTML` to prevent XSS (exception: trusted template literals building layout structure, not inserting user data)

### Landing Page (frontend/landing/index.html)

Single HTML file. No external dependencies except Google Fonts.

Content:
- Header: `AHLYX LABS` in large cyan monospace, subtitle: `Security tooling by Ahlyx`
- Three tool cards in a grid:
  - **Security Enrichment API** — "Threat intelligence aggregation across 8 sources" — link to `/enrichment`
  - **Network Scanner** — "TCP port scanning with OT/ICS protocol detection" — link to `/scanner`
  - **Hardware Dashboard** — "Live system metrics: CPU, RAM, disk, network" — link to `/hardware`
- Footer: `github.com/Ahlyx` + Twitter `@AhIyxx`
- Each card has: tool name, one-line description, a `[ LAUNCH ]` button styled as a terminal command

### Enrichment Frontend (frontend/enrichment/)

**Preserve the existing frontend from `static/` in the enrichment repo.** It already works against the Go backend's JSON schemas and has a polished design. Copy it in as-is, then make two changes:
1. Update `API_BASE` to point to `https://api.ahlyx.tools` in production (keep `http://localhost:8080` as the dev fallback with a comment)
2. Add a `[ ← BACK ]` link in the header that goes to `/`

### Scanner Frontend (frontend/scanner/index.html)

Single file. Rewrite fresh with the shared design system.

Layout:
- Header: `NETWORK SCANNER` + subtitle `TCP port scan with OT/ICS detection`
- Input row: text input for subnet/IP + `[ SCAN ]` button
- Status line below input (shows "Scanning...", "Found N host(s)", errors)
- Results table: IP ADDRESS | OPEN PORTS
  - OT-flagged ports: `--threat` color + `⚠ OT` suffix
  - Normal ports: `--dim` color
  - No ports: `"none"` in muted style
- `[ ← BACK ]` link in header

API call: `GET https://api.ahlyx.tools/api/v1/scanner/scan?subnet={subnet}`

Note: remove MAC/vendor columns since the Go backend returns `null` for MAC. The table is IP + ports only.

### Hardware Frontend (frontend/hardware/)

Three files matching the existing hardware dashboard structure. Rewrite fresh with the shared design system applied consistently.

Layout:
- Header: `HARDWARE DASHBOARD` + subtitle + auto-refresh indicator showing last updated timestamp
- System info card (full width)
- 2-column grid: CPU | RAM
- Disk card (full width, shows each partition as a block)
- Network card (full width, shows each interface as a block + totals)

API base: `https://api.ahlyx.tools/api/v1/hardware` in production, `http://localhost:8080/api/v1/hardware` in dev.

Auto-refresh every 2 seconds (same as original). Use `textContent` for all data values.

Add `[ ← BACK ]` link in header.

### vercel.json (frontend/vercel.json)

```json
{
  "rewrites": [
    { "source": "/enrichment/(.*)", "destination": "/enrichment/index.html" },
    { "source": "/scanner/(.*)", "destination": "/scanner/index.html" },
    { "source": "/hardware/(.*)", "destination": "/hardware/index.html" },
    { "source": "/(.*)", "destination": "/landing/index.html" }
  ]
}
```

---

## Deployment Config

### Dockerfile

Multi-stage build identical to the existing enrichment scanner-go Dockerfile:

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o ahlyx-labs ./cmd/server

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/ahlyx-labs /ahlyx-labs
EXPOSE 8080
ENTRYPOINT ["/ahlyx-labs"]
```

### Environment Variables (.env.example)

```env
# Enrichment API keys
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
IPINFO_API_KEY=
OTX_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
URLSCAN_API_KEY=

# Optional
PORT=8080
CACHE_TTL_SECONDS=3600
```

Hardware and scanner require no API keys.

### Render

- Service type: Web Service
- Build command: `docker build -t ahlyx-labs .`
- Start command: `/ahlyx-labs`
- Set all env vars in Render dashboard
- Custom domain: `api.ahlyx.tools`

### Vercel

- Root directory: `frontend/`
- Framework preset: Other (static)
- Build command: none
- Output directory: `./`
- Custom domain: `ahlyx.tools`

---

## CLAUDE.md (for the repo root)

```markdown
# CLAUDE.md

## Project
Ahlyx Labs — unified security tools platform. Single Go binary + multi-frontend static site.

## Commands
# Run backend
go run ./cmd/server

# Build binary
go build -ldflags="-s -w" -o ahlyx-labs ./cmd/server

# Run tests
go test ./...

# Build Docker image
docker build -t ahlyx-labs .

## Architecture
- Backend: Go 1.22, chi router, one binary, three tool packages
- Frontend: Vanilla JS/HTML/CSS, no build step, deployed to Vercel
- Docs: api.ahlyx.tools (Render) / ahlyx.tools (Vercel)

## Rules
- All Go code lives in internal/ — no business logic in cmd/
- All frontend code lives in frontend/ — one subfolder per tool
- shared/ package is used by all three tools — no tool-specific code goes there
- Do NOT use innerHTML to insert user-supplied data — use textContent or createElement
- Do NOT modify .env files
- Maintain JSON response parity with original enrichment API schemas (pointer types for optional fields)
- Scanner /24 hard limit is a security control — do not remove it
```

---

## Build Order for Claude Code

Execute in this order to avoid import cycle issues and allow testing at each stage:

1. `go.mod` + `go.sum` initialization
2. `internal/shared/` — cache, config, ratelimit, middleware, response helpers
3. `internal/enrichment/models/` — all structs
4. `internal/enrichment/validators/` 
5. `internal/enrichment/services/` — all 11 service files
6. `internal/enrichment/handlers/` — ip, domain, url, hash, helpers
7. `internal/scanner/` — ports, scanner, models, handlers
8. `internal/hardware/` — models, handlers
9. `cmd/server/main.go` — wire everything together
10. `Dockerfile` + `.env.example`
11. `frontend/landing/index.html`
12. `frontend/enrichment/` — copy + update API_BASE + add back link
13. `frontend/scanner/index.html`
14. `frontend/hardware/` — full rewrite with shared design system
15. `frontend/vercel.json`
16. `README.md`

---

## Notes on Baptisia

Baptisia (the ICS/OT DSL compiler) is a standalone CLI tool — it has no API surface and no frontend. Do **not** include it in the ahlyx-labs monorepo. It lives as its own repo and can be linked from the landing page as a separate project card if desired.

If you want to add it to the landing page, add a fourth card:
- **Baptisia** — "Safety-enforcing DSL for ICS/OT systems, compiles to C" — link to `https://github.com/Ahlyx/Baptisia`