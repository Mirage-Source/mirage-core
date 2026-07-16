# MIRAGE Honeypot Dataset — v5

Generated from live capture data. Snapshot covers **102,402 sessions** across **797 unique source IPs**.

## Headline finding

**99,926 of 102,402 sessions (97.58%) executed zero commands** after authentication. The remainder (2.42%) reached the interactive shell and executed real commands — the honeypot is no longer purely a credential-stuffing sink.

## SSH client banners

| Banner | Sessions |
|---|---|
| `SSH-2.0-Go` | 96,923 |
| `SSH-2.0-libssh_0.9.6` | 2,514 |
| *(unknown — rejected sessions recorded before this was tracked)* | 1,189 |
| `SSH-2.0-OpenSSH_7.4` | 580 |
| `SSH-2.0-libssh_0.7.4` | 560 |
| `SSH-2.0-libssh_0.11.1` | 398 |
| `SSH-2.0-PuTTY_Release_0.84` | 164 |
| `SSH-2.0-AsyncSSH_2.1.0` | 22 |
| `SSH-2.0-paramiko_5.0.0` | 13 |
| `SSH-2.0-libssh2_1.10.0` | 9 |

## Coordinated infrastructure

Groups of 3+ distinct source IPs that authenticated with the same credential via the same SSH client banner within the same 5-minute window — a real signal of a single script/botnet driving multiple source IPs, not just IPs that happen to share a lifetime session count.

### 3 IPs — `root:checking!@!@%` via `SSH-2.0-Go`

- **Window:** 2026-07-12 02:05 UTC (5-minute bucket)
- **IPs:** 103.98.149.87, 77.94.47.83, 80.66.85.226
- **ASN breakdown:** Maxserver Company Limited (1), Telecom Media Systems JLLC (1), SERV.HOST GROUP LTD (1)
- **Country breakdown:** VN (1), BY (1), DE (1)

### 3 IPs — `root:p@ssword` via `SSH-2.0-Go`

- **Window:** 2026-06-24 01:25 UTC (5-minute bucket)
- **IPs:** 176.65.132.129, 192.109.200.78, 91.92.42.7
- **ASN breakdown:** Pfcloud UG (haftungsbeschrankt) (2), LLC VASH KREDIT BANK (1)
- **Country breakdown:** NL (3)

### 3 IPs — `aaa:123456` via `SSH-2.0-Go`

- **Window:** 2026-06-24 01:20 UTC (5-minute bucket)
- **IPs:** 176.65.132.129, 192.109.200.78, 91.92.42.7
- **ASN breakdown:** Pfcloud UG (haftungsbeschrankt) (2), LLC VASH KREDIT BANK (1)
- **Country breakdown:** NL (3)

### 3 IPs — `root:test123` via `SSH-2.0-Go`

- **Window:** 2026-06-24 01:15 UTC (5-minute bucket)
- **IPs:** 176.65.132.129, 192.109.200.78, 91.92.42.7
- **ASN breakdown:** Pfcloud UG (haftungsbeschrankt) (2), LLC VASH KREDIT BANK (1)
- **Country breakdown:** NL (3)

## Top source ASNs (full dataset)

| ASN Name | Sessions |
|---|---|
| Pfcloud UG (haftungsbeschrankt) | 33,331 |
| TELEINDIA NETWORKS PRIVATE LIMITED | 13,082 |
| LLC VASH KREDIT BANK | 7,857 |
| Netnam Company | 7,692 |
| Datacamp Limited | 7,562 |
| Offshore LC | 5,570 |
| UNMANAGED LTD | 3,624 |
| RoyaleHosting BV | 3,555 |
| Fiba Cloud Operation Company, LLC | 1,522 |
| Netiface Limited | 689 |

## Top source countries (full dataset)

| Country | Sessions |
|---|---|
| NL | 50,441 |
| IN | 13,477 |
| GB | 10,009 |
| VN | 8,711 |
| BG | 7,017 |
| US | 5,622 |
| CN | 1,318 |
| DE | 1,091 |
| AD | 657 |
| SE | 320 |

## Data notes

- 33 of 797 source IPs could not be resolved to an ASN in this snapshot's pinned DB-IP data (coverage gap, not a classification result).
- `attacker_class` and `classifier_confidence` in the underlying dataset currently reflect interpretable weak-label heuristics (banner signature, auth pattern), not a trained ML classifier. A trained behavioural classifier is in development; this snapshot predates it.
- ASN/country attribution: [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

*Generated 2026-07-16 13:36 UTC. Dataset version: v5.*