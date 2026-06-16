# MIRAGE

**AI-augmented SSH honeypot for attacker behavioral analysis and threat intelligence generation.**

MIRAGE exposes a convincing fake SSH server, lets attackers in, studies their behavior through an adaptive AI-generated shell environment, plants deliberate bait to extract intelligence, and produces structured threat intelligence output. It is a purely defensive research tool deployed on infrastructure we own.

---

## How it works

When an attacker connects to MIRAGE's SSH port, they are presented with a realistic Ubuntu 22.04 shell. Every keystroke, command, inter-command timing, and credential attempt is captured. A background ML pipeline enriches each session with behavioral embeddings, attacker classification, and MITRE ATT&CK technique mappings. The result is structured threat intelligence that goes beyond static indicators of compromise.

```
Attacker
   │
   │  SSH
   ▼
Go Honeypot (mirage-core)
   │  writes sessions
   ▼
PostgreSQL
   │  polls unenriched sessions
   ▼
Python ML Worker (ml-worker)
   │  timing heuristics · tool signatures · transformer embeddings
   ▼
PostgreSQL  ←  enriched with attacker class + 128-d behavioral embedding
```

---

## Architecture

| Component | Language | Role |
|-----------|----------|------|
| `core/` | Go | SSH server, fake shell, session capture, PostgreSQL persistence |
| `bridge/` | Python | Polling worker, schema adapter, ML pipeline orchestration |
| `ml/` | Python / PyTorch | Dual-channel Transformer, timing heuristics, tool signature detection |
| `db/` | SQL | PostgreSQL schema — core tables and ML intelligence tables |

**Go core** handles all network I/O. It accepts any SSH credentials, presents a fake interactive shell, and captures structured session data including auth attempts, commands with sequence numbers and inter-command delays, and bait file interactions.

**ML worker** runs asynchronously. It polls PostgreSQL for unenriched sessions and produces:
- Coefficient of Variation of inter-command intervals (bot vs. human signal)
- Regex-based tool signature detection (Mirai, XMRig, and others)
- 128-dimensional behavioral embedding from a dual-channel Transformer encoder
- Attacker classification: automated scanner · script kiddie · manual recon · APT-level

**Graceful degradation** — the ML worker runs in heuristics-only mode if no trained model checkpoint is present. Timing analysis and tool signatures still produce useful output without a GPU or pre-trained weights.

---

## Attacker classification

The Transformer treats an SSH session as a marked temporal point process. It receives two input channels simultaneously:

- **Token channel** — tokenized command sequence
- **Timing channel** — log-scaled inter-command intervals (ICI)

This fusion allows the model to distinguish, for example, a bot running `wget` in 12ms from a human running the same command after a 3-second pause — even when the command content is identical.

---

## Threat intelligence output

Each enriched session produces:

- Full session JSON with auth attempts, command trace, and timing data
- Attacker class label and confidence
- 128-d behavioral embedding for clustering and re-identification
- MITRE ATT&CK technique mappings *(Milestone 5)*
- STIX 2.1 bundle export *(Milestone 5)*

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
# Edit .env with your database password

# 3. Generate SSH host key
./scripts/generate_hostkey.sh
# On Windows: ./scripts/generate_hostkey.ps1

# 4. Start all services
docker compose up --build
```

The honeypot listens on port `22` (production) and `2222` (testing). PostgreSQL is internal only.

### With ML model (optional)

To enable 128-d embeddings, place trained artifacts in `./artifacts/`:

```
artifacts/
└── embedder/
    ├── best.pt
    └── tokenizer/
```

Then uncomment the model environment variables in `docker-compose.yml`.

---

## Repository structure

```
mirage-core/
├── core/               # Go SSH honeypot
│   ├── cmd/mirage/     # Entrypoint
│   ├── internal/server # SSH server and session lifecycle
│   ├── internal/shell  # Fake shell state machine
│   ├── internal/session# Session data model
│   └── internal/store  # PostgreSQL persistence
├── bridge/             # Python ML worker
├── ml/                 # PyTorch models and analysis pipeline
├── db/init/            # PostgreSQL schema migrations
├── scripts/            # Host key generation utilities
├── tests/              # Python test suite
└── artifacts/          # Model checkpoints (not committed)
```

---

## Ethical and legal notice

MIRAGE is deployed exclusively on infrastructure owned by the authors. It is designed for defensive security research. Do not deploy on infrastructure you do not own or have explicit written authorization to operate on.

---

## Authors

**Vinayak** — Go infrastructure, SSH layer, session pipeline
**Devang** — ML pipeline, behavioral embeddings, attacker classification
