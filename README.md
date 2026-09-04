# MIRAGE

**Production SSH honeypot and threat intelligence platform for measuring automated attacker behaviour at scale.**

MIRAGE exposes a convincing fake SSH server, captures every credential attempt and session, and produces structured threat intelligence output. It is a purely defensive research tool deployed on infrastructure we own.

---

## Live findings

MIRAGE runs on a Nuremberg VPS, collecting since 2026-08-30. An earlier
deployment in Frankfurt ran until 2026-08-26; its data is published separately
as dataset versions `v1`-`v6` and is not continuous with the current series. As
of the latest snapshot:

<!-- STATS:START -->
- **10,094 sessions** captured from **249 unique source IPs** (2,150 in the last 24h)
- Most repeated credential pair: `support` / `support` (98 attempts)
- **7 coordinated credential-stuffing windows** identified, across 32 distinct IPs sharing the same credential and SSH client banner within a 5-minute window

_Last updated automatically: 2026-09-04T02:00:20Z_
<!-- STATS:END -->

The block above is regenerated automatically from the live dataset (see [Keeping this README current](#keeping-this-readme-current)). Sessions that authenticate against the seeded weak-credential list go on to interact with a stateful fake shell; the rest are rejected like a real, minimally hardened `sshd` would reject them.

→ [Published dataset and findings report](https://github.com/Mirage-Source/mirage-core/blob/gh-pages/dataset/latest/REPORT.md)
→ [mirage-web](https://github.com/Mirage-Source/mirage-web) — the public dashboard and operator console over this same sensor

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
| `internal/validity/` | Go | Data-validity checks (accept-rate drift, field cardinality, campaign decomposition, heartbeat gaps) served at `/dashboard` |
| `internal/deception/` | Go | Deception-policy client, and the gate deciding which unknown commands may get an LLM-generated response |
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
| `GET /api/export/commands` | Full command export, cursor-paginated (`?after=`, `?limit=`) |
| `GET /api/sensors` | Configured dashboard sensors |
| `GET /api/validity/summary` | All four data-validity checks for one sensor (`?sensor=`) |
| `GET /api/validity/accept-rate` | Accept-rate band-drift series (`?sensor=`, `?days=`) |
| `GET /api/validity/fields` | Field-cardinality collapse status (`?sensor=`) |
| `GET /api/validity/campaign` | Campaign-vs-aggregate decomposition (`?sensor=`) |
| `GET /api/validity/heartbeat` | Sensor uptime / downtime gaps (`?sensor=`) |
| `GET /api/llm-shell/providers` | Configured LLM completion providers, active one, live counters |
| `POST /api/llm-shell/active` | Switch the active LLM completion provider |
| `GET /dashboard` | The data-validity dashboard (`?api_key=` — see below) |

API access is available to researchers on request. All routes require an
`X-API-Key` header or `Authorization: Bearer` token, except `/dashboard`,
which also accepts the key as `?api_key=` since a browser navigation can't
set a custom header — see `DECISIONS.md` for the trade-off that implies.

Prometheus and Grafana have been retired in favor of `/dashboard` — see
the data-validity toolkit section below.

### Data-validity toolkit

`internal/validity` implements four standing checks generalizing the
[preprint](#citation)'s data-validity audit, so the next silent corruption
gets caught automatically instead of waiting for an outside reviewer:

1. **Accept-rate band drift** — a rolling control chart on daily auth
   success rate; flags a day that falls outside its own trailing history.
2. **Field cardinality collapse** — watches a fixed set of fields that
   should vary (`sessions.outcome`, `auth_attempts.success`, SSH banner,
   attacker class, deception action, ingress source) for a silent collapse
   to one value.
3. **Campaign-vs-aggregate decomposition** — the preprint's
   wordlist-divisibility + credential-set-identity campaign test, run live,
   with headline stats computed both including and excluding the detected
   campaign.
4. **Downtime-vs-silence separation** — a sensor heartbeat independent of
   session traffic, so "the sensor was down" and "nobody connected" are
   never conflated.

All four are computed periodically and served at `/dashboard` and the
`/api/validity/*` endpoints above.

### LLM shell completion

The simulated shell answers a fixed set of builtins with curated,
self-consistent output. Everything else has always returned
`bash: <cmd>: command not found` — both a fingerprint and a dead end, against
a corpus where only 2.79% of sessions issue any command at all.

With `MIRAGE_LLM_SHELL_ENABLED=true`, commands with no builtin (`uptime`,
`nproc`, `lspci`, `nvidia-smi`, ...) are instead answered by a configured LLM
provider. Responses are cached per session, so the same command asked twice
returns byte-identical output.

Providers are declared in `MIRAGE_LLM_SHELL_PROVIDERS_JSON` and switched live
from `/dashboard`. Two kinds are supported: `anthropic`, and
`openai_compatible` — which covers OpenAI proper *and* self-hosted servers
speaking the same API (Ollama, vLLM, LM Studio) via `base_url`. Config names
the environment variable holding each key, never the key itself.

**This never fires for** a command the shell already implements, a compound
line (`;` `&&` `|` `>` `$()` ...), or an egress-capable tool (`wget`, `curl`,
`nc`, `ssh`, package managers, language interpreters). Those keep resolving
exactly as before. See the rules of engagement in
[SECURITY.md](SECURITY.md#rules-of-engagement) — the constraint is enforced by
tests that share a command list with the existing no-egress battery, not by
the generation prompt.

Cost is bounded by a per-session cap and a global sliding-window rate limit,
and a circuit breaker stops calling a failing provider. Every refusal path
degrades to the ordinary `command not found`, so the honeypot behaves exactly
as it always has whenever a completion can't be served.

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

Deploying to a real VPS rather than a local machine? See
[DEPLOYMENT.md](DEPLOYMENT.md) first — it covers the things this quick-start
doesn't: moving real admin SSH off port 22 before it conflicts with the
honeypot, the schema catch-up migrations a fresh clone needs, and wiring up
`mirage-web`.

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

---

## Citation

If you use MIRAGE or its dataset in academic work, please cite the accompanying
preprint (see `CITATION.cff`):

> Vinayak Tyagi and Devang Verma. "MIRAGE: A Labeled SSH Honeypot Dataset, and
> What Auditing It Revealed About Honeypot Data Validity." Preprint, 2026.
> OSF: https://doi.org/10.17605/OSF.IO/JM4E7

_The preprint is a publicly available manuscript and has not yet been peer-reviewed._

---

## License

- **Source code** is licensed under the [Apache License 2.0](LICENSE).
- **The published MIRAGE dataset** (session exports, `commands.jsonl`, report, and
  the archived OSF snapshot) is licensed separately under
  [CC BY 4.0](DATASET_LICENSE.md).

Contributions are welcome under these terms — see [CONTRIBUTING.md](CONTRIBUTING.md),
which requires a Developer Certificate of Origin sign-off (`git commit -s`).
