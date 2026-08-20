# MIRAGE Dataset License

The **MIRAGE dataset** — the published session-level export and all files derived
from it, including `sessions.csv` / `sessions.json`, `commands.jsonl`,
`stats_summary.json`, `REPORT.md`, and the archived OSF snapshot — is licensed
under the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**.

> This license applies to **data and findings**, not to source code. The MIRAGE
> source code in this repository is licensed separately under the Apache License,
> Version 2.0 (see `LICENSE`).

## You are free to

- **Share** — copy and redistribute the dataset in any medium or format.
- **Adapt** — remix, transform, and build upon the dataset for any purpose,
  including commercially.

## Under the following term

- **Attribution** — You must give appropriate credit, provide a link to the
  license, and indicate if changes were made. You may do so in any reasonable
  manner, but not in any way that suggests the licensor endorses you or your use.

Full legal code: https://creativecommons.org/licenses/by/4.0/legalcode

## How to attribute

If you use the MIRAGE dataset in academic work, please cite the accompanying
preprint (see `CITATION.cff`):

> Vinayak Tyagi and Devang Verma. "MIRAGE: A Labeled SSH Honeypot Dataset, and
> What Auditing It Revealed About Honeypot Data Validity." Preprint, 2026.
> OSF: https://doi.org/10.17605/OSF.IO/JM4E7

## Third-party data

Geographic and ASN attribution (`asn`, `country` fields) is derived from
[DB-IP](https://db-ip.com), also licensed under CC BY 4.0. Any redistribution of
the geo-enriched fields must preserve DB-IP attribution.

## Note on anonymization

Client IP addresses in `commands.jsonl` are anonymized by default (salted hash).
Users of the dataset must not attempt to re-identify individuals or deanonymize
source addresses beyond what the project already publishes.
