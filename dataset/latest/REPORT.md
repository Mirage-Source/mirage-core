# MIRAGE Honeypot Dataset — v1

Generated from live capture data. Snapshot covers **52,572 sessions** across **117 unique source IPs**.

## Headline finding

**52,572 of 52,572 sessions (100.0%) executed zero commands** after authentication. Every captured session in this snapshot consists entirely of automated credential-stuffing attempts against the SSH auth layer — no attacker has reached the interactive shell.

## SSH client banners

| Banner | Sessions |
|---|---|
| `SSH-2.0-Go` | 52,559 |
| `SSH-2.0-paramiko_5.0.0` | 9 |
| `SSH-2.0-libssh2_1.11.0` | 3 |
| `SSH-2.0-libssh_0.10.6` | 1 |

## Coordinated infrastructure

Groups of source IPs sharing an identical session count — a signal of scripted, centrally-orchestrated behaviour rather than independent scanners hitting similar numbers by chance.

### 6 IPs at exactly 1,522 sessions each

- **ASN breakdown:** Pfcloud UG (haftungsbeschrankt) (5), LLC VASH KREDIT BANK (1)
- **Country breakdown:** NL (6)

### 21 IPs at exactly 761 sessions each

- **ASN breakdown:** Pfcloud UG (haftungsbeschrankt) (10), Offshore LC (6), LLC VASH KREDIT BANK (2), Fiba Cloud Operation Company, LLC (1)
- **Country breakdown:** NL (18), BG (2), US (1)
- **2 IP(s) unresolved** (outside this snapshot's geo data coverage)

### 3 IPs at exactly 24 sessions each

- **ASN breakdown:** TECHOFF SRV LIMITED (2), Omegatech LTD (1)
- **Country breakdown:** AD (2), NL (1)

### 4 IPs at exactly 2 sessions each

- **ASN breakdown:** CHINA UNICOM China169 Backbone (1), Offshore LC (1), RACK SPHERE HOSTING S.A. (1), DigitalOcean, LLC (1)
- **Country breakdown:** CN (1), NL (1), CH (1), DE (1)

## Top source ASNs (full dataset)

| ASN Name | Sessions |
|---|---|
| Pfcloud UG (haftungsbeschrankt) | 17,503 |
| TELEINDIA NETWORKS PRIVATE LIMITED | 13,082 |
| Datacamp Limited | 7,562 |
| Offshore LC | 5,570 |
| LLC VASH KREDIT BANK | 3,044 |
| Fiba Cloud Operation Company, LLC | 761 |
| UNMANAGED LTD | 562 |
| Netiface Limited | 447 |
| TECHOFF SRV LIMITED | 251 |
| M/S Bhola Dot Net | 74 |

## Top source countries (full dataset)

| Country | Sessions |
|---|---|
| NL | 26,763 |
| IN | 13,102 |
| GB | 7,563 |
| BG | 3,516 |
| US | 769 |
| DE | 450 |
| AD | 251 |
| BD | 74 |
| CN | 36 |
| SG | 35 |

## Data notes

- 16 of 117 source IPs could not be resolved to an ASN in this snapshot's pinned DB-IP data (coverage gap, not a classification result).
- `attacker_class` and `classifier_confidence` in the underlying dataset currently reflect interpretable weak-label heuristics (banner signature, auth pattern), not a trained ML classifier. A trained behavioural classifier is in development; this snapshot predates it.
- ASN/country attribution: [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

*Generated 2026-06-30 20:33 UTC. Dataset version: v1.*