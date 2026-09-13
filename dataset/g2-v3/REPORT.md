# MIRAGE Honeypot Dataset — g2-v3

Generated from live capture data. Snapshot covers **88,964 sessions** across **2010 unique source IPs**.

## Headline finding

**85,826 of 88,964 sessions (96.47%) executed zero commands** after authentication. The remainder (3.53%) reached the interactive shell and executed real commands — the honeypot is no longer purely a credential-stuffing sink.

## SSH client banners

| Banner | Sessions |
|---|---|
| `SSH-2.0-Go` | 73,502 |
| `SSH-2.0-libssh_0.9.6` | 12,294 |
| `SSH-2.0-libssh_0.11.1` | 977 |
| `SSH-2.0-PuTTY_Release_0.84` | 621 |
| `SSH-2.0-JSCH_2.28.6` | 478 |
| `SSH-2.0-libssh2_1.11.0` | 255 |
| `SSH-2.0-OpenSSH_10.4` | 197 |
| `SSH-2.0-<img src=x onerror="alert('you can be pwned ^_^')">` | 124 |
| `SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3` | 121 |
| `SSH-2.0-libssh_0.12.0` | 106 |

## Coordinated infrastructure

Groups of 3+ distinct source IPs that authenticated with the same credential via the same SSH client banner within the same 5-minute window — a real signal of a single script/botnet driving multiple source IPs, not just IPs that happen to share a lifetime session count.

### 33 IPs — `root:s3qu3nc3r` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:30 UTC (5-minute bucket)
- **IPs:** 103.10.120.8, 103.35.123.67, 113.21.229.194, 133.18.142.16, 14.225.239.154, 146.185.246.180, 148.69.64.217, 152.70.144.156, 176.79.86.115, 178.18.196.174, 180.210.130.30, 181.115.146.102, 185.205.112.17, 188.132.200.177, 191.100.22.249, 193.160.223.177, 195.34.106.205, 196.28.236.219, 213.85.70.206, 27.118.20.168, 37.113.131.241, 37.34.138.115, 41.204.161.214, 51.210.142.53, 62.169.180.28, 62.38.192.68, 65.21.119.150, 74.129.4.16, 78.36.202.91, 91.244.115.95, 91.93.57.195, 92.204.128.28, 95.0.99.65
- **ASN breakdown:** PT Sumber Data Indonesia (1), Net for Choice (1), Triangle Services (1), KAGOYA JAPAN Inc. (1), VIETNAM POSTS AND TELECOMMUNICATIONS GROUP (1), Unikalnie Technologii ltd. (1), Vodafone Portugal - Communicacoes Pessoais S.A. (1), Oracle Corporation (1), MEO - SERVICOS DE COMUNICACOES E MULTIMEDIA S.A. (1), Eclit Bilisim Hizmetleri A.S (1), Bangla Phone Ltd (1), Entel S.A. - EntelNet (1), ALCORT INGENIERIA Y ASESORIA S.L. (1), Ozkula Internet Hizmetleri Tic. LTD. STI. (1), ETAPA EP (1), 23M GmbH (1), A1 Bulgaria EAD (1), TMCEL - Moçambique Telecom, SA (1), "Central Telegraph" Public Joint-stock Company (1), Hanel Communication JSC (1), JSC "ER-Telecom Holding" (1), Mobile Telecommunications Company (1), Kenya Education Network (1), OVH SAS (1), pc3100Plus, s.r.o. (1), VODAFONE-PANAFON HELLENIC TELECOMMUNICATIONS COMPANY SA (1), Hetzner Online GmbH (1), Charter Communications Inc (1), PJSC Rostelecom (1), WIRENET LLC (1), Superonline Iletisim Hizmetleri A.S. (1), GoDaddy.com, LLC (1), Turk Telekomunikasyon Anonim Sirketi (1)
- **Country breakdown:** RU (5), TR (4), US (3), BD (2), VN (2), PT (2), ID (1), IN (1), JP (1), BO (1), ES (1), EC (1), DE (1), BG (1), MZ (1), KW (1), KE (1), FR (1), SK (1), GR (1), FI (1)

### 32 IPs — `wallet:w@ll3t` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:30 UTC (5-minute bucket)
- **IPs:** 103.10.120.8, 103.35.123.67, 113.176.64.34, 113.21.229.194, 133.18.142.16, 14.225.239.154, 146.185.246.180, 148.69.64.217, 152.70.144.156, 176.79.86.115, 177.74.253.226, 178.18.196.174, 180.210.130.30, 181.115.146.102, 185.205.112.17, 188.132.200.177, 191.100.22.249, 193.187.172.166, 195.34.106.205, 213.147.113.186, 213.85.70.206, 27.118.20.168, 37.113.131.241, 37.34.138.115, 41.204.161.214, 51.210.142.53, 65.21.119.150, 74.129.4.16, 78.36.202.91, 91.93.57.195, 92.204.128.28, 95.0.99.65
- **ASN breakdown:** PT Sumber Data Indonesia (1), Net for Choice (1), VNPT Corp (1), Triangle Services (1), KAGOYA JAPAN Inc. (1), VIETNAM POSTS AND TELECOMMUNICATIONS GROUP (1), Unikalnie Technologii ltd. (1), Vodafone Portugal - Communicacoes Pessoais S.A. (1), Oracle Corporation (1), MEO - SERVICOS DE COMUNICACOES E MULTIMEDIA S.A. (1), UNIFIQUE TELECOMUNICACOES S/A (1), Eclit Bilisim Hizmetleri A.S (1), Bangla Phone Ltd (1), Entel S.A. - EntelNet (1), ALCORT INGENIERIA Y ASESORIA S.L. (1), Ozkula Internet Hizmetleri Tic. LTD. STI. (1), ETAPA EP (1), JSC Selectel (1), A1 Bulgaria EAD (1), A1 Hrvatska d.o.o. (1), "Central Telegraph" Public Joint-stock Company (1), Hanel Communication JSC (1), JSC "ER-Telecom Holding" (1), Mobile Telecommunications Company (1), Kenya Education Network (1), OVH SAS (1), Hetzner Online GmbH (1), Charter Communications Inc (1), PJSC Rostelecom (1), Superonline Iletisim Hizmetleri A.S. (1), GoDaddy.com, LLC (1), Turk Telekomunikasyon Anonim Sirketi (1)
- **Country breakdown:** RU (5), TR (4), VN (3), US (3), BD (2), PT (2), ID (1), IN (1), JP (1), BR (1), BO (1), ES (1), EC (1), BG (1), HR (1), KW (1), KE (1), FR (1), FI (1)

### 30 IPs — `root:12345678` via `SSH-2.0-Go`

- **Window:** 2026-09-07 15:45 UTC (5-minute bucket)
- **IPs:** 103.173.112.10, 103.214.100.4, 103.44.149.142, 144.76.171.137, 159.138.118.174, 161.248.223.131, 161.97.181.164, 167.114.57.4, 167.71.218.26, 167.86.91.48, 177.69.6.210, 181.115.178.163, 185.205.112.17, 186.47.99.110, 187.18.8.5, 190.128.200.138, 190.57.149.194, 191.97.106.92, 210.245.30.140, 220.241.0.1, 27.118.20.168, 41.111.187.130, 41.111.198.172, 5.196.45.62, 50.229.116.170, 77.229.68.86, 77.50.186.234, 79.174.68.129, 91.208.194.40, 92.222.247.184
- **ASN breakdown:** OVH SAS (3), Contabo GmbH (2), Telecom Algeria (2), SIXTH STAR TECHNOLOGIES (1), PT SURYA TEKNIKA PRATAMA (1), PT Semesta Teknologi Informatika (1), Hetzner Online GmbH (1), HUAWEI INTERNATIONAL PTE. LTD. (1), Iamem It Consulting (1), DigitalOcean, LLC (1), ALGAR TELECOM S/A (1), Entel S.A. - EntelNet (1), ALCORT INGENIERIA Y ASESORIA S.L. (1), CORPORACION NACIONAL DE TELECOMUNICACIONES - CNT EP (1), COMPUTADORES E SISTEMAS LTDA (1), Telecel S.A. (1), PUNTONET S.A. (1), COLUMBUS NETWORKS DOMINICANA, S.A. (1), FPT Telecom Company (1), PCCW IMS Ltd (PCCW Business Internet Access) (1), Hanel Communication JSC (1), Comcast Cable Communications, LLC (1), VODAFONE ESPANA S.A.U. (1), MEGASVYAZ LLC (1), JSC "RU-CENTER" (1), Art-master LLC (1)
- **Country breakdown:** DE (3), IN (2), ID (2), BR (2), ES (2), EC (2), VN (2), DZ (2), FR (2), RU (2), CL (1), CA (1), SG (1), BO (1), PY (1), DO (1), HK (1), US (1), UA (1)

### 29 IPs — `root:1522023` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:30 UTC (5-minute bucket)
- **IPs:** 103.10.120.8, 103.35.123.67, 113.176.64.34, 113.21.229.194, 115.127.77.92, 14.225.239.154, 148.69.64.217, 152.70.144.156, 176.79.86.115, 178.18.196.174, 180.210.130.30, 181.115.146.102, 185.205.112.17, 188.132.200.177, 191.100.22.249, 193.187.172.166, 195.34.106.205, 196.28.236.219, 213.147.113.186, 213.85.70.206, 37.113.131.241, 37.34.138.115, 41.204.161.214, 51.210.142.53, 74.129.4.16, 78.36.202.91, 91.244.115.95, 92.204.128.28, 95.0.99.65
- **ASN breakdown:** PT Sumber Data Indonesia (1), Net for Choice (1), VNPT Corp (1), Triangle Services (1), BRACNet Limited (1), VIETNAM POSTS AND TELECOMMUNICATIONS GROUP (1), Vodafone Portugal - Communicacoes Pessoais S.A. (1), Oracle Corporation (1), MEO - SERVICOS DE COMUNICACOES E MULTIMEDIA S.A. (1), Eclit Bilisim Hizmetleri A.S (1), Bangla Phone Ltd (1), Entel S.A. - EntelNet (1), ALCORT INGENIERIA Y ASESORIA S.L. (1), Ozkula Internet Hizmetleri Tic. LTD. STI. (1), ETAPA EP (1), JSC Selectel (1), A1 Bulgaria EAD (1), TMCEL - Moçambique Telecom, SA (1), A1 Hrvatska d.o.o. (1), "Central Telegraph" Public Joint-stock Company (1), JSC "ER-Telecom Holding" (1), Mobile Telecommunications Company (1), Kenya Education Network (1), OVH SAS (1), Charter Communications Inc (1), PJSC Rostelecom (1), WIRENET LLC (1), GoDaddy.com, LLC (1), Turk Telekomunikasyon Anonim Sirketi (1)
- **Country breakdown:** RU (5), BD (3), US (3), TR (3), VN (2), PT (2), ID (1), IN (1), BO (1), ES (1), EC (1), BG (1), MZ (1), HR (1), KW (1), KE (1), FR (1)

### 28 IPs — `root:12345678` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:15 UTC (5-minute bucket)
- **IPs:** 113.21.229.196, 113.53.62.169, 123.24.143.250, 14.241.150.101, 146.185.246.180, 162.241.43.213, 170.81.136.243, 181.177.241.110, 183.179.44.89, 187.72.10.114, 189.59.89.147, 193.90.12.230, 194.124.40.165, 194.28.89.220, 202.93.27.36, 203.184.52.117, 213.6.207.62, 220.241.162.209, 27.118.20.168, 31.199.224.56, 38.146.27.70, 41.75.123.75, 45.230.133.51, 77.229.68.86, 81.10.39.215, 91.223.205.251, 91.82.58.77, 94.53.199.67
- **ASN breakdown:** VNPT Corp (2), Triangle Services (1), TOT Public Company Limited (1), Unikalnie Technologii ltd. (1), Network Solutions, LLC (1), ALAGOAS TRIBUNAL DE CONTAS DO ESTADO DE ALAGOAS (1), OPTICAL TECHNOLOGIES S.A.C. (1), Hong Kong Broadband Network Limited (1), ALGAR TELECOM S/A (1), TELEFÔNICA BRASIL S.A (1), GLOBALCONNECT AS (1), 23M GmbH (1), Agronet LLC (1), Thamrin Telekomunikasi Network PT. (1), Two Degrees Mobile Limited (1), Palestine Telecommunications Company (PALTEL) (1), PCCW IMS Ltd (PCCW Business Internet Access) (1), Hanel Communication JSC (1), Telecom Italia S.p.A. (1), Cogent Communications (1), Inq. Digital Limited (1), YOO FIBRA (1), VODAFONE ESPANA S.A.U. (1), TE-AS (1), Information-Transport Network Company ltd. (1), Invitech ICT Services Kft. (1), NEXTGEN COMMUNICATIONS SRL (1)
- **Country breakdown:** BR (4), VN (3), RU (2), US (2), HK (2), BD (1), TH (1), PE (1), NO (1), DE (1), ID (1), NZ (1), PS (1), IT (1), MW (1), ES (1), EG (1), UA (1), HU (1), RO (1)

### 20 IPs — `root:12345678` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:50 UTC (5-minute bucket)
- **IPs:** 103.148.165.50, 103.20.219.5, 109.195.36.14, 113.21.229.196, 14.225.239.154, 145.249.125.36, 162.241.43.213, 168.194.255.192, 172.104.135.139, 181.177.241.110, 188.166.50.125, 189.21.40.242, 200.201.194.8, 213.42.31.237, 213.6.207.62, 45.230.133.51, 45.86.82.219, 74.129.4.16, 88.157.220.46, 94.130.94.42
- **ASN breakdown:** Net for Choice (1), Diskominfo Kabupaten Humbang Hasundutan (1), JSC "ER-Telecom Holding" (1), Triangle Services (1), VIETNAM POSTS AND TELECOMMUNICATIONS GROUP (1), Kar-Tel LLC (1), Network Solutions, LLC (1), WAVE PLUS INTERNET LTDA ME (1), Akamai Technologies, Inc. (1), OPTICAL TECHNOLOGIES S.A.C. (1), DigitalOcean, LLC (1), TIM S/A (1), DC MATRIX INTERNET S/A (1), EMIRATES TELECOMMUNICATIONS GROUP COMPANY (ETISALAT GROUP) PJSC (1), Palestine Telecommunications Company (PALTEL) (1), YOO FIBRA (1), NLS ASTANA LLP (1), Charter Communications Inc (1), NOS COMUNICACOES, S.A. (1), Hetzner Online GmbH (1)
- **Country breakdown:** BR (4), KZ (2), US (2), DE (2), IN (1), ID (1), RU (1), BD (1), VN (1), PE (1), NL (1), AE (1), PS (1), PT (1)

### 17 IPs — `root:12345678` via `SSH-2.0-Go`

- **Window:** 2026-09-07 17:20 UTC (5-minute bucket)
- **IPs:** 103.10.120.8, 14.225.239.154, 145.239.252.176, 152.70.144.156, 170.81.136.243, 180.180.249.36, 190.151.113.6, 191.6.67.3, 193.238.38.47, 194.28.89.220, 200.60.129.244, 202.93.27.36, 203.187.225.252, 45.230.133.51, 46.10.201.91, 51.83.143.147, 93.84.120.135
- **ASN breakdown:** OVH SAS (2), PT Sumber Data Indonesia (1), VIETNAM POSTS AND TELECOMMUNICATIONS GROUP (1), Oracle Corporation (1), ALAGOAS TRIBUNAL DE CONTAS DO ESTADO DE ALAGOAS (1), TOT Public Company Limited (1), ENTEL CHILE S.A. (1), portal provedor de comunicações ltda (1), The private businessman Buryanov Konstantin Volodimirovich (1), Agronet LLC (1), Telefonica del Peru S.A.A. (1), Thamrin Telekomunikasi Network PT. (1), YOU Broadband & Cable India Ltd. (1), YOO FIBRA (1), Vivacom Bulgaria EAD (1), Republican Unitary Telecommunication Enterprise Beltelecom (1)
- **Country breakdown:** BR (3), ID (2), VN (1), GB (1), US (1), TH (1), CL (1), UA (1), RU (1), PE (1), IN (1), BG (1), PL (1), BY (1)

### 16 IPs — `root:12345678` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:45 UTC (5-minute bucket)
- **IPs:** 102.16.48.130, 103.31.132.189, 129.126.149.198, 154.16.114.112, 162.241.130.19, 163.47.33.70, 170.254.28.244, 185.97.114.218, 187.141.172.82, 189.59.89.147, 38.77.155.39, 41.94.1.199, 45.236.242.200, 65.21.119.150, 86.62.112.66, 93.84.120.135
- **ASN breakdown:** Telecom Malagasy (1), PT. Arthatama Adhiprima Persada (1), M1 NET LTD (1), WHG Hosting Services Ltd (1), Network Solutions, LLC (1), Link3 Technologies Limited (1), María Teresa Vivar (CITYCOM) (1), NLS Kazakhstan LLC (1), Uninet S.A. de C.V. (1), TELEFÔNICA BRASIL S.A (1), Zingo Media Group LLC (1), Mozambique Research & Education Network - MoRENet (1), SIDI SERVIÇOS DE COMUNICAÇÃO LTDA-ME (1), Hetzner Online GmbH (1), JSC "ER-Telecom Holding" (1), Republican Unitary Telecommunication Enterprise Beltelecom (1)
- **Country breakdown:** US (3), BR (2), MG (1), ID (1), SG (1), BD (1), EC (1), KZ (1), MX (1), MZ (1), FI (1), RU (1), BY (1)

### 15 IPs — `ubuntu:QWERTYUIOP` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:40 UTC (5-minute bucket)
- **IPs:** 103.173.112.10, 103.28.38.102, 114.9.97.2, 138.201.58.132, 14.225.239.154, 148.223.251.51, 151.80.213.177, 176.236.28.42, 181.214.83.147, 185.97.114.218, 188.165.245.160, 200.105.94.68, 202.57.50.43, 80.253.22.34, 84.51.9.103
- **ASN breakdown:** OVH SAS (2), Superonline Iletisim Hizmetleri A.S. (2), SIXTH STAR TECHNOLOGIES (1), NhanHoa Software company (1), Hetzner Online GmbH (1), VIETNAM POSTS AND TELECOMMUNICATIONS GROUP (1), Uninet S.A. de C.V. (1), WHG Hosting Services Ltd (1), NLS Kazakhstan LLC (1), Telecom Argentina S.A. (1), PhilCom Corporation (1), JOINT-STOCK COMPANY "TELEPORT TELECOM" (1)
- **Country breakdown:** VN (2), TR (2), IN (1), ID (1), DE (1), MX (1), PL (1), BR (1), KZ (1), FR (1), AR (1), PH (1), RU (1)
- **1 IP(s) unresolved** (outside this snapshot's geo data coverage)

### 14 IPs — `ubuntu:QWERTY` via `SSH-2.0-Go`

- **Window:** 2026-09-07 16:45 UTC (5-minute bucket)
- **IPs:** 160.22.240.235, 177.126.90.235, 179.61.137.164, 183.91.15.184, 186.16.210.130, 190.220.150.162, 191.100.22.249, 41.111.198.172, 5.196.45.62, 5.9.119.162, 51.210.100.146, 77.109.21.190, 92.204.128.28, 93.84.120.135
- **ASN breakdown:** OVH SAS (2), PT Seeplus Media Transformasi (1), NOVA TELECOM LTDA (1), WHG Hosting Services Ltd (1), CMC Telecom Infrastructure Company (1), Telecel S.A. (1), Techtel LMDS Comunicaciones Interactivas S.A. (1), ETAPA EP (1), Telecom Algeria (1), Hetzner Online GmbH (1), PJSC Telesystems of Ukraine (1), GoDaddy.com, LLC (1), Republican Unitary Telecommunication Enterprise Beltelecom (1)
- **Country breakdown:** US (2), FR (2), ID (1), BR (1), VN (1), PY (1), AR (1), EC (1), DZ (1), DE (1), UA (1), BY (1)

## Top source ASNs (full dataset)

| ASN Name | Sessions |
|---|---|
| "Euro Crypt" EOOD | 18,324 |
| OVH SAS | 4,659 |
| noris network AG | 4,140 |
| UNMANAGED LTD | 3,875 |
| DigitalOcean, LLC | 1,941 |
| TRI TELECOM LTDA | 1,885 |
| LLC VASH KREDIT BANK | 1,569 |
| Microsoft Corporation | 1,469 |
| TECHOFF SRV LIMITED | 1,221 |
| Hetzner Online GmbH | 1,218 |

## Top source countries (full dataset)

| Country | Sessions |
|---|---|
| US | 22,225 |
| NL | 8,531 |
| DE | 6,035 |
| ID | 5,757 |
| BR | 5,448 |
| RU | 4,269 |
| IN | 3,914 |
| GB | 3,267 |
| VN | 2,341 |
| FR | 1,727 |

## Data notes

- 27 of 2010 source IPs could not be resolved to an ASN in this snapshot's pinned DB-IP data (coverage gap, not a classification result).
- `attacker_class` and `classifier_confidence` in the underlying dataset currently reflect interpretable weak-label heuristics (banner signature, auth pattern), not a trained ML classifier. A trained behavioural classifier is in development; this snapshot predates it.
- ASN/country attribution: [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

*Generated 2026-09-13 08:02 UTC. Dataset version: g2-v3.*