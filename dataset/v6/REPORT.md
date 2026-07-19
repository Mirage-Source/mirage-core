# MIRAGE Honeypot Dataset — v6

Generated from live capture data. Snapshot covers **111,419 sessions** across **976 unique source IPs**.

## Headline finding

**108,621 of 111,419 sessions (97.49%) executed zero commands** after authentication. The remainder (2.51%) reached the interactive shell and executed real commands — the honeypot is no longer purely a credential-stuffing sink.

## SSH client banners

| Banner | Sessions |
|---|---|
| `SSH-2.0-Go` | 102,030 |
| `SSH-2.0-libssh_0.9.6` | 4,948 |
| *(unknown — rejected sessions recorded before this was tracked)* | 1,189 |
| `SSH-2.0-libssh_0.7.4` | 858 |
| `SSH-2.0-OpenSSH_7.4` | 809 |
| `SSH-2.0-libssh_0.11.1` | 730 |
| `SSH-2.0-libssh_0.9.5` | 500 |
| `SSH-2.0-PuTTY_Release_0.84` | 245 |
| `SSH-2.0-AsyncSSH_2.1.0` | 41 |
| `SSH-2.0-libssh2_1.10.0` | 15 |

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
| Pfcloud UG (haftungsbeschrankt) | 34,092 |
| TELEINDIA NETWORKS PRIVATE LIMITED | 13,082 |
| LLC VASH KREDIT BANK | 8,222 |
| Netnam Company | 7,692 |
| Datacamp Limited | 7,562 |
| Offshore LC | 5,570 |
| UNMANAGED LTD | 3,737 |
| RoyaleHosting BV | 3,555 |
| Fiba Cloud Operation Company, LLC | 1,522 |
| TECHOFF SRV LIMITED | 1,475 |

## Top source countries (full dataset)

| Country | Sessions |
|---|---|
| NL | 51,652 |
| IN | 13,584 |
| GB | 10,891 |
| VN | 9,268 |
| BG | 8,546 |
| US | 5,973 |
| CN | 1,970 |
| AD | 1,475 |
| DE | 1,258 |
| MX | 657 |

## Data notes

- 37 of 976 source IPs could not be resolved to an ASN in this snapshot's pinned DB-IP data (coverage gap, not a classification result).
- `attacker_class` and `classifier_confidence` in the underlying dataset currently reflect interpretable weak-label heuristics (banner signature, auth pattern), not a trained ML classifier. A trained behavioural classifier is in development; this snapshot predates it.
- ASN/country attribution: [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

*Generated 2026-07-19 05:49 UTC. Dataset version: v6.*