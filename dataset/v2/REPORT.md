# MIRAGE Honeypot Dataset — v2

Generated from live capture data. Snapshot covers **63,195 sessions** across **152 unique source IPs**.

## Headline finding

**63,195 of 63,195 sessions (100.0%) executed zero commands** after authentication. Every captured session in this snapshot consists entirely of automated credential-stuffing attempts against the SSH auth layer — no attacker has reached the interactive shell.

## SSH client banners

| Banner | Sessions |
|---|---|
| `SSH-2.0-Go` | 63,176 |
| `SSH-2.0-paramiko_5.0.0` | 11 |
| `SSH-2.0-libssh2_1.11.0` | 4 |
| `SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1` | 2 |
| `SSH-2.0-AsyncSSH_2.23.0` | 1 |
| `SSH-2.0-libssh_0.10.6` | 1 |

## Coordinated infrastructure

Groups of source IPs sharing an identical session count — a signal of scripted, centrally-orchestrated behaviour rather than independent scanners hitting similar numbers by chance.

### 7 IPs at exactly 1,522 sessions each

- **ASN breakdown:** Pfcloud UG (haftungsbeschrankt) (4), LLC VASH KREDIT BANK (2), Fiba Cloud Operation Company, LLC (1)
- **Country breakdown:** NL (6), US (1)

### 27 IPs at exactly 761 sessions each

- **ASN breakdown:** Pfcloud UG (haftungsbeschrankt) (14), Offshore LC (6), LLC VASH KREDIT BANK (4)
- **Country breakdown:** NL (24), BG (3)
- **3 IP(s) unresolved** (outside this snapshot's geo data coverage)

### 6 IPs at exactly 2 sessions each

- **ASN breakdown:** CHINA UNICOM China169 Backbone (1), Offshore LC (1), PT. Telekomunikasi Selular (1), Canal + Telecom SAS (1), DigitalOcean, LLC (1), NetLab Global (1)
- **Country breakdown:** CN (1), NL (1), ID (1), GP (1), DE (1), US (1)

## Top source ASNs (full dataset)

| ASN Name | Sessions |
|---|---|
| Pfcloud UG (haftungsbeschrankt) | 22,069 |
| TELEINDIA NETWORKS PRIVATE LIMITED | 13,082 |
| Datacamp Limited | 7,562 |
| LLC VASH KREDIT BANK | 6,088 |
| Offshore LC | 5,570 |
| Fiba Cloud Operation Company, LLC | 1,522 |
| UNMANAGED LTD | 1,405 |
| Netiface Limited | 516 |
| TECHOFF SRV LIMITED | 402 |
| M/S Bhola Dot Net | 77 |

## Top source countries (full dataset)

| Country | Sessions |
|---|---|
| NL | 35,224 |
| IN | 13,104 |
| GB | 7,563 |
| BG | 4,615 |
| US | 1,534 |
| DE | 519 |
| AD | 402 |
| BD | 77 |
| SG | 70 |
| CN | 65 |

## Data notes

- 19 of 152 source IPs could not be resolved to an ASN in this snapshot's pinned DB-IP data (coverage gap, not a classification result).
- `attacker_class` and `classifier_confidence` in the underlying dataset currently reflect interpretable weak-label heuristics (banner signature, auth pattern), not a trained ML classifier. A trained behavioural classifier is in development; this snapshot predates it.
- ASN/country attribution: [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

*Generated 2026-07-05 06:39 UTC. Dataset version: v2.*