# MIRAGE Honeypot Dataset — v3

Generated from live capture data. Snapshot covers **75,092 sessions** across **199 unique source IPs**.

## Headline finding

**73,553 of 75,092 sessions (97.95%) executed zero commands** after authentication. The remainder (2.05%) reached the interactive shell and executed real commands — the honeypot is no longer purely a credential-stuffing sink.

## SSH client banners

| Banner | Sessions |
|---|---|
| `SSH-2.0-Go` | 73,869 |
| *(unknown — rejected sessions recorded before this was tracked)* | 1,189 |
| `SSH-2.0-paramiko_5.0.0` | 12 |
| `SSH-2.0-OpenSSH_7.4` | 5 |
| `SSH-2.0-libssh2_1.11.0` | 5 |
| `SSH-2.0-AsyncSSH_2.23.0` | 4 |
| `SSH-2.0-libssh_0.9.6` | 2 |
| `SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2` | 2 |
| `SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2+rpt1` | 2 |
| `SSH-2.0-libssh_0.11.1` | 1 |

## Coordinated infrastructure

Groups of 3+ distinct source IPs that authenticated with the same credential via the same SSH client banner within the same 5-minute window — a real signal of a single script/botnet driving multiple source IPs, not just IPs that happen to share a lifetime session count.

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
| Pfcloud UG (haftungsbeschrankt) | 28,006 |
| TELEINDIA NETWORKS PRIVATE LIMITED | 13,082 |
| Datacamp Limited | 7,562 |
| LLC VASH KREDIT BANK | 6,951 |
| Offshore LC | 5,570 |
| UNMANAGED LTD | 2,490 |
| Fiba Cloud Operation Company, LLC | 1,522 |
| Netiface Limited | 635 |
| TECHOFF SRV LIMITED | 576 |
| VPSVAULT.HOST LTD | 248 |

## Top source countries (full dataset)

| Country | Sessions |
|---|---|
| NL | 43,126 |
| IN | 13,166 |
| GB | 8,266 |
| BG | 6,066 |
| US | 1,536 |
| DE | 639 |
| AD | 576 |
| SE | 248 |
| SG | 88 |
| CN | 80 |

## Data notes

- 25 of 199 source IPs could not be resolved to an ASN in this snapshot's pinned DB-IP data (coverage gap, not a classification result).
- `attacker_class` and `classifier_confidence` in the underlying dataset currently reflect interpretable weak-label heuristics (banner signature, auth pattern), not a trained ML classifier. A trained behavioural classifier is in development; this snapshot predates it.
- ASN/country attribution: [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

*Generated 2026-07-11 22:16 UTC. Dataset version: v3.*