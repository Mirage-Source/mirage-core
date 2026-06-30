# MIRAGE

**Production SSH honeypot and threat intelligence platform for measuring automated attacker behaviour at scale.**

MIRAGE exposes a convincing fake SSH server, captures every credential attempt and session, and produces structured threat intelligence output. It is a purely defensive research tool deployed on infrastructure we own.

---

## Live findings

MIRAGE has been running continuously since June 16, 2026 on a Frankfurt VPS. As of the latest snapshot:

- **52,517 sessions** captured from **117 unique source IPs**
- **100% of sessions executed zero commands** — every attacker disconnected after credential submission, none reached the interactive shell
- **27-IP coordinated botnet** identified across 3 NL-registered ASNs, maintaining a precise 2:1 session-count ratio across all nodes (1,522 vs 761 sessions), consistent with centralised C2 orchestration
- Persistent credential campaigns targeting blockchain infrastructure usernames (`node`, `solana`, `validator`, `eth-docker`) observed every day of the capture window

→ [Published dataset and findings report](https://github.com/Mirage-Source/mirage-core/blob/gh-pages/dataset/latest/REPORT.md)

---

## How it works

When an attacker connects to MIRAGE's SSH port, they are accepted with any credential and presented with a stateful fake shell. Every auth attempt, SSH client banner, and session timing signal is captured and persisted to PostgreSQL. A background ML worker enriches each session with attacker classification and MITRE ATT&CK technique mappings. The result is structured threat intelligence queryable via a secured REST API.

```
Attacker
   │
   │  SSH
   ▼
Go Honeypot (mirage-core)
   │  writes sessions + auth attempts
   ▼
PostgreSQL
   │  polls unenriched sessions
   ▼
Python ML Worker (ml-worker)
   │  banner heuristics · timing signals · weak-label classification
   ▼
PostgreSQL  ←  enriched with attacker_class, mitre_techniques, stix_bundle
```

---

## Architecture

| Component | Language | Role |
|-----------|----------|------|
| `cmd/mirage/` | Go | SSH server entrypoint |
| `cmd/api/` | Go | REST API entrypoint |
| `internal/server/` | Go | SSH server, session lifecycle |
| `internal/shell/` | Go | Stateful fake shell (ls, cd, cat, whoami, pwd, echo) |
| `internal/session/` | Go | Session data model |
| `internal/store/` | Go | PostgreSQL persistence |
| `bridge/` | Python | Polling worker, schema adapter, ML pipeline orchestration |
| `ml/` | Python / PyTorch | Classifier, timing heuristics, tool signature detection |
| `db/init/` | SQL | PostgreSQL schema migrations |
| `scripts/` | Python | Dataset export, geo enrichment, report generation |
| `data/geo/` | CSV | Pinned DB-IP ASN/country snapshots for geo attribution |

**Go core** handles all network I/O. It accepts any SSH credentials, adds a randomised auth delay (500–3000ms) to slow credential stuffers, presents a fake interactive shell, and captures structured session data.

**ML worker** runs asynchronously, polling PostgreSQL for unenriched sessions. It currently runs in heuristics-only mode (no trained checkpoint deployed yet), producing:
- Interpretable weak-label attacker classification based on banner and auth signals
- MITRE ATT&CK technique mappings (T1110, T1110.001, T1078)
- STIX 2.1 bundle generation (gated behind `MIRAGE_STIX_ENABLED`)

A dual-channel Transformer encoder (token sequence + log-scaled inter-command timing) is implemented and awaiting a trained checkpoint. Once deployed, it will replace the current weak-label fallback with calibrated behavioural classifications.

---

## Dataset

A versioned public dataset is published weekly from the live sensor. Each release includes:

- `sessions.csv` / `sessions.json` — full session export with ASN/country attribution
- `stats_summary.json` — aggregate statistics
- `REPORT.md` — findings narrative

**Latest release:** https://github.com/Mirage-Source/mirage-core/blob/gh-pages/dataset/latest/REPORT.md

Raw data: https://mirage-source.github.io/mirage-core/dataset/latest/sessions.csv

Geo attribution: [DB-IP](https://db-ip.com), CC BY 4.0.

---

## REST API

A secured REST API exposes the live dataset. All endpoints require an `X-API-Key` header.

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Aggregate statistics, coordinated IP groups, hourly distribution |
| `GET /api/sessions` | Paginated session list |
| `GET /api/sessions/{id}` | Full session with ML intelligence overlay |
| `GET /api/sessions/{id}/report` | Structured report with embedded STIX 2.1 bundle |
| `GET /api/export` | Full session export (used by the weekly dataset job) |
| `GET /metrics` | Prometheus metrics |

API access is available to researchers on request.

---

## Setup

### Prerequisites

- Docker and Docker Compose
- OpenSSH (for host key generation)

### First-time setup

```bash
# 1. Clone the repository
git clone https://github.com/Mirage-Source/mirage-core.git
cd mirage-core

# 2. Configure environment
cp .env.example .env
# Edit .env with your database credentials and API key

# 3. Generate SSH host key
./scripts/generate_hostkey.sh
# On Windows: ./scripts/generate_hostkey.ps1

# 4. Start all services
docker compose up --build
```

The honeypot listens on port `22` (production) and `2222` (testing/management). PostgreSQL is internal only.

### With ML classifier (optional)

To enable trained classification, place a checkpoint at the path referenced by `MIRAGE_CLASSIFIER_CHECKPOINT` in your `.env`. Without it, the ML worker runs in heuristics-only mode — timing analysis and weak-label classification still produce useful output.

---

## Ethical and legal notice

MIRAGE is deployed exclusively on infrastructure owned by the authors. It is designed for defensive security research and does not scan, probe, or retaliate against any observed IP. Do not deploy on infrastructure you do not own or have explicit written authorisation to operate on.

---

## Authors

**Vinayak Tyagi** — Go infrastructure, SSH server, session pipeline, REST API, DevOps, deployment

**Devang Verma** — ML pipeline, behavioural classification, PyTorch models
