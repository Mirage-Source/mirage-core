# MIRAGE

**Production SSH honeypot and threat intelligence platform for measuring automated attacker behaviour at scale.**

MIRAGE exposes a convincing fake SSH server, captures every credential attempt and session, and produces structured threat intelligence output. It is a purely defensive research tool deployed on infrastructure we own.

---

## Live findings

MIRAGE has been running continuously on a Frankfurt VPS. As of the latest snapshot:

<!-- STATS:START -->
- **115,211 sessions** captured from **1,044 unique source IPs** (3,792 in the last 24h)
- Most repeated credential pair: `support` / `support` (304 attempts)
- **4 coordinated credential-stuffing windows** identified, across 6 distinct IPs sharing the same credential and SSH client banner within a 5-minute window

_Last updated automatically: 2026-07-22T02:24:09Z_
<!-- STATS:END -->

The block above is regenerated automatically from the live dataset (see [Keeping this README current](#keeping-this-readme-current)). Sessions that authenticate against the seeded weak-credential list go on to interact with a stateful fake shell; the rest are rejected like a real, minimally hardened `sshd` would reject them.

→ [Published dataset and findings report](https://github.com/Mirage-Source/mirage-core/blob/gh-pages/dataset/latest/REPORT.md)

---

## How it works

When an attacker connects to MIRAGE's SSH port, their credentials are checked against a seeded list of real-world weak credentials; a match is accepted into a stateful fake shell, everything else is rejected like a real server would reject it. Every auth attempt, SSH client banner, and session timing signal is captured and persisted to PostgreSQL. A background ML worker enriches each session with attacker classification, MITRE ATT&CK technique mappings, and severity scoring. The result is structured threat intelligence queryable via a secured REST API.

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
| `internal/shell/` | Go | Stateful fake shell, unified filesystem tree, `;`/`&&`/`||` chaining, `$(...)` substitution |
| `internal/session/` | Go | Session data model |
| `internal/store/` | Go | PostgreSQL persistence |
| `bridge/` | Python | Polling worker, schema adapter, ML pipeline orchestration |
| `ml/` | Python / PyTorch | Classifier, timing heuristics, tool signature detection |
| `db/init/` | SQL | PostgreSQL schema migrations |
| `scripts/` | Python | Dataset export, geo enrichment, report generation |
| `data/geo/` | CSV | Pinned DB-IP ASN/country snapshots for geo attribution |

**Go core** handles all network I/O. It checks SSH credentials against a seeded weak-credential list, adds a randomised auth delay (500–3000ms) to slow credential stuffers, presents a fake interactive shell backed by a single consistent filesystem tree (including bait files that generate real, recorded triggers when accessed), and captures structured session data.

**ML worker** runs asynchronously, polling PostgreSQL for unenriched sessions. It currently runs in heuristics-only mode (no trained checkpoint deployed yet), producing:
- Interpretable weak-label attacker classification based on banner and auth signals
- MITRE ATT&CK technique mappings (T1110, T1110.001, T1078)
- Severity scoring and recommended actions
- STIX 2.1 bundle generation (enabled by default)

A dual-channel Transformer encoder (token sequence + log-scaled inter-command timing) is implemented and awaiting a trained checkpoint. Once deployed, it will replace the current weak-label fallback with calibrated behavioural classifications.

---

## Dataset

A versioned public dataset is published weekly from the live sensor. Each release includes:

- `sessions.csv` / `sessions.json` — full session export with ASN/country attribution
- `commands.jsonl` — every captured command/response pair, one JSON object per line, with session context (attacker class, MITRE techniques) and bait-hit flags inlined on each row. Suited for training/fine-tuning on real attacker command sequences. Client IPs are anonymized (salted hash) by default in this file.
- `stats_summary.json` — aggregate statistics
- `REPORT.md` — findings narrative

**Latest release:** https://github.com/Mirage-Source/mirage-core/blob/gh-pages/dataset/latest/REPORT.md

Raw data: https://mirage-source.github.io/mirage-core/dataset/latest/sessions.csv
Commands: https://mirage-source.github.io/mirage-core/dataset/latest/commands.jsonl

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

## Keeping this README current

The **Live findings** block above is not hand-maintained. A scheduled workflow
(`.github/workflows/update-stats.yml`) pulls `GET /api/stats` from the live
API daily, publishes it as `stats.json` on `gh-pages`, and runs
`scripts/update_readme_stats.py` to rewrite the marked block in the Live
findings section on `main`, committing the result automatically. To run it
by hand:

```bash
python3 scripts/update_readme_stats.py --stats path/to/stats.json --readme README.md
```

---

## Ethical and legal notice

MIRAGE is deployed exclusively on infrastructure owned by the authors. It is designed for defensive security research and does not scan, probe, or retaliate against any observed IP. Do not deploy on infrastructure you do not own or have explicit written authorisation to operate on.

---

## Authors

**Vinayak Tyagi** — Go infrastructure, SSH server, session pipeline, REST API, DevOps, deployment

**Devang Verma** — ML pipeline / Intellegence Layer, behavioural classification, RL Policy , 
