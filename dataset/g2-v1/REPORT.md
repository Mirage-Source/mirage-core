# MIRAGE Honeypot Dataset — g2-v1

Generated from live capture data. Snapshot covers **9,733 sessions** across **242 unique source IPs**.

## Headline finding

**9,122 of 9,733 sessions (93.72%) executed zero commands** after authentication. The remainder (6.28%) reached the interactive shell and executed real commands — the honeypot is no longer purely a credential-stuffing sink.

## SSH client banners

| Banner | Sessions |
|---|---|
| `SSH-2.0-libssh_0.9.6` | 5,104 |
| `SSH-2.0-Go` | 4,066 |
| `SSH-2.0-libssh_0.11.1` | 403 |
| `SSH-2.0-PuTTY_Release_0.84` | 73 |
| `SSH-2.0-libssh2_1.11.0` | 36 |
| `SSH-2.0-AsyncSSH_2.1.0` | 35 |
| `SSH-2.0-libssh2_1.11.1` | 7 |
| `SSH-2.0-libssh_0.12.0` | 5 |
| `SSH-2.0-russh_0.51.1` | 2 |
| `SSH-2.0-sshcustom_0.1` | 2 |

## Coordinated infrastructure

Groups of 3+ distinct source IPs that authenticated with the same credential via the same SSH client banner within the same 5-minute window — a real signal of a single script/botnet driving multiple source IPs, not just IPs that happen to share a lifetime session count.

### 7 IPs — `root:e6@D=@=2SP+r0Fa` via `SSH-2.0-Go`

- **Window:** 2026-08-30 16:20 UTC (5-minute bucket)
- **IPs:** 144.217.17.154, 159.223.59.82, 177.65.107.197, 192.151.255.195, 216.232.226.203, 58.149.235.226, 74.194.191.52
- **ASN breakdown:** OVH SAS (1), DigitalOcean, LLC (1), Claro NXT Telecomunicacoes Ltda (1), POWER LINE (HK) CO., LIMITED (1), TELUS Communications Inc. (1), LG DACOM Corporation (1), Suddenlink Communications (1)
- **Country breakdown:** CA (2), US (2), SG (1), BR (1), KR (1)

### 7 IPs — `root:e6@D=@=2SP+r0Fa` via `SSH-2.0-Go`

- **Window:** 2026-08-30 15:50 UTC (5-minute bucket)
- **IPs:** 144.31.164.253, 210.178.251.33, 43.160.253.60, 44.201.226.243, 72.60.205.253, 75.111.120.108, 88.148.90.140
- **ASN breakdown:** PLAY2GO INTERNATIONAL LIMITED (1), Korea Telecom (1), Shenzhen Tencent Computer Systems Company Limited (1), Amazon.com, Inc. (1), Hostinger International Limited (1), Suddenlink Communications (1), AIRE NETWORKS DEL MEDITERRANEO SL UNIPERSONAL (1)
- **Country breakdown:** US (2), DE (1), KR (1), SG (1), IN (1), ES (1)

### 5 IPs — `root:e6@D=@=2SP+r0Fa` via `SSH-2.0-Go`

- **Window:** 2026-08-30 16:10 UTC (5-minute bucket)
- **IPs:** 103.49.62.60, 164.132.101.40, 182.208.27.219, 66.116.243.149, 74.194.200.229
- **ASN breakdown:** Zenlayer Inc (1), OVH SAS (1), LG POWERCOMM (1), Oracle Corporation (1), Suddenlink Communications (1)
- **Country breakdown:** HK (1), FR (1), KR (1), IN (1), US (1)

### 4 IPs — `root:e6@D=@=2SP+r0Fa` via `SSH-2.0-Go`

- **Window:** 2026-08-30 15:45 UTC (5-minute bucket)
- **IPs:** 192.227.173.105, 24.188.9.179, 64.227.168.220, 78.72.57.203
- **ASN breakdown:** HostPapa (1), Cablevision Systems Corp. (1), DigitalOcean, LLC (1), Telia Company AB (1)
- **Country breakdown:** US (2), IN (1), SE (1)

### 3 IPs — `server:123123` via `SSH-2.0-libssh_0.9.6`

- **Window:** 2026-08-30 20:00 UTC (5-minute bucket)
- **IPs:** 171.25.158.57, 66.94.113.255, 69.6.234.27
- **ASN breakdown:** Patrik Lagerman (1), Contabo Inc. (1), Oracle Corporation (1)
- **Country breakdown:** SE (1), US (1), CO (1)

### 3 IPs — `root:e6@D=@=2SP+r0Fa` via `SSH-2.0-Go`

- **Window:** 2026-08-30 16:15 UTC (5-minute bucket)
- **IPs:** 162.198.46.77, 43.161.219.111, 5.180.19.218
- **ASN breakdown:** AT&T Enterprises, LLC (1), Shenzhen Tencent Computer Systems Company Limited (1), Yug-Telecom-K Ltd. (1)
- **Country breakdown:** US (1), HK (1), RU (1)

### 3 IPs — `root:e6@D=@=2SP+r0Fa` via `SSH-2.0-Go`

- **Window:** 2026-08-30 16:00 UTC (5-minute bucket)
- **IPs:** 112.146.101.75, 136.29.52.7, 217.154.163.54
- **ASN breakdown:** LG POWERCOMM (1), Webpass Inc. (1), IONOS SE (1)
- **Country breakdown:** KR (1), US (1), DE (1)

## Top source ASNs (full dataset)

| ASN Name | Sessions |
|---|---|
| UNMANAGED LTD | 966 |
| LLC VASH KREDIT BANK | 784 |
| Microsoft Corporation | 512 |
| DigitalOcean, LLC | 495 |
| Hetzner Online GmbH | 459 |
| OVH SAS | 404 |
| Korea Telecom | 199 |
| Oracle Corporation | 197 |
| TECHOFF SRV LIMITED | 186 |
| Shenzhen Tencent Computer Systems Company Limited | 180 |

## Top source countries (full dataset)

| Country | Sessions |
|---|---|
| NL | 1,906 |
| GB | 1,109 |
| US | 743 |
| IN | 546 |
| CN | 482 |
| BR | 439 |
| DE | 419 |
| FR | 315 |
| SG | 304 |
| ID | 299 |

## Data notes

- 6 of 242 source IPs could not be resolved to an ASN in this snapshot's pinned DB-IP data (coverage gap, not a classification result).
- `attacker_class` and `classifier_confidence` in the underlying dataset currently reflect interpretable weak-label heuristics (banner signature, auth pattern), not a trained ML classifier. A trained behavioural classifier is in development; this snapshot predates it.
- ASN/country attribution: [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

*Generated 2026-09-03 21:57 UTC. Dataset version: g2-v1.*