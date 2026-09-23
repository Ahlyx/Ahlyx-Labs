# Ahlyx Labs

Ahlyx Labs is an independent security and software lab focused on security
tools, systems work, and research. This repository contains the source for the
[Ahlyx Labs website](https://ahlyxlabs.com), its Go API backend, and automated
checks.

- [Website](https://ahlyxlabs.com)
- [GitHub organization](https://github.com/Ahlyx)
- [This repository](https://github.com/Ahlyx/Ahlyx-Labs)
- [API](https://api.ahlyxlabs.com)

The site is built with static HTML, CSS, and JavaScript. A Go service provides
the public API.

## Explore the site

- [Projects and lab](https://ahlyxlabs.com/lab) — project summaries, status,
  source links, and hosted tools.
- [Security research](https://ahlyxlabs.com/research) — published findings and
  disclosure writeups, including [RustChain](https://ahlyxlabs.com/research/rustchain)
  and [OneDragon](https://ahlyxlabs.com/research/onedragon).
- [Notes](https://ahlyxlabs.com/notes) — practical writeups on systems,
  security, and infrastructure. Read [SEO for a Tiny Technical Site](https://ahlyxlabs.com/notes/seo)
  or [Custom Domain Email](https://ahlyxlabs.com/notes/custom-domain-email),
  or subscribe to the [RSS feed](https://ahlyxlabs.com/notes/feed.xml).
- [Services](https://ahlyxlabs.com/services) — small, fixed-scope security
  reviews and developer tooling work.
- [Security and trust](https://ahlyxlabs.com/security) — official channels and
  vulnerability reporting.
- [Privacy policy](https://ahlyxlabs.com/privacy)
- [llms.txt](https://ahlyxlabs.com/llms.txt) — a machine-readable site and
  project summary.

## Projects and tools

| Project | What it does | Links |
|---|---|---|
| AuditMCP | Local-first MCP audit logging proxy | [Project](https://ahlyxlabs.com/lab/auditmcp) · [Source](https://github.com/Ahlyx/auditmcp) |
| Conveyance | Research into phone-approved MCP requests | [Project](https://ahlyxlabs.com/lab/conveyance) · [Source](https://github.com/Ahlyx/Conveyance) |
| Security Enrichment | Go API for IP, domain, URL, and hash enrichment | [Project](https://ahlyxlabs.com/lab/security-enrichment) · [Tool](https://ahlyxlabs.com/enrichment) · [Source](https://github.com/Ahlyx/Ahlyx-Labs/tree/master/internal/enrichment) |
| Baptisia | Experimental compiler for ICS/OT control programs | [Project](https://ahlyxlabs.com/lab/baptisia) · [Source](https://github.com/Ahlyx/Baptisia) |
| PCAP Agent | Local packet capture and browser-based analysis | [Project](https://ahlyxlabs.com/lab/pcap-agent) · [Dashboard](https://ahlyxlabs.com/pcap) · [Source](https://github.com/Ahlyx/pcap-agent) |
| Network Scanner | Local scanner for authorized lab networks | [Project](https://ahlyxlabs.com/lab/network-scanner) · [Source](https://github.com/Ahlyx/Network-Scanner) |
| Hardware Dashboard | Displays aggregate telemetry from the hosted backend | [Project](https://ahlyxlabs.com/lab/hardware-dashboard) · [Dashboard](https://ahlyxlabs.com/hardware) |

The PCAP dashboard requires the local agent. The Network Scanner is intended
for authorized local or isolated lab networks; hosted scanning is disabled in
normal production.

## API overview

The API base URL is [`https://api.ahlyxlabs.com`](https://api.ahlyxlabs.com).
The enrichment service exposes:

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/ip/{address}` | IP enrichment |
| `GET /api/v1/domain/{name}` | Domain enrichment |
| `POST /api/v1/url` | URL enrichment using a JSON request body |
| `GET /api/v1/hash/{hash}` | File hash enrichment |
| `GET /api/v1/capabilities` | Reports available API capabilities |

See the [Security Enrichment project page](https://ahlyxlabs.com/lab/security-enrichment#api)
for request details. Results depend on available sources and configuration; no
result should be treated as proof that an indicator is safe. Do not submit
passwords, API keys, private links, or other secrets to public lookup services.
URLScan submission requires operator enablement and explicit visitor opt-in.

## Repository map

```text
cmd/server/          Go API entry point
internal/
  enrichment/        Enrichment handlers, models, providers, and validation
  hardware/          Host telemetry handlers and models
  pcap/              PCAP relay sessions and handlers
  scanner/           Scanner implementation and guarded handler
  shared/            Configuration, cache, database, middleware, and limits
frontend/
  assets/             Shared styles, scripts, and brand assets
  landing/            Homepage and privacy page
  lab/                Project directory and project pages
  research/           Research index and disclosure reports
  notes/              Notes, articles, and RSS feed
  enrichment/         Enrichment interface
  pcap/                PCAP dashboard
  hardware/            Hardware dashboard
  services/            Services page
  security/            Security and trust page
  vercel.json          Site routes, redirects, and response headers
tests/                 Go and browser-side checks
.github/workflows/     CI workflow for Go and frontend checks
Dockerfile             Container build for the Go backend
.env.example           Backend configuration variable names
go.mod, go.sum         Go module and dependency checksums
.gitignore             Local environment and build-output exclusions
```

For questions or project inquiries, email [alex@ahlyxlabs.com](mailto:alex@ahlyxlabs.com).
