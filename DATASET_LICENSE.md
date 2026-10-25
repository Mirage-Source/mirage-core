# MIRAGE Dataset License

The **MIRAGE dataset** — the published session-level export and all files derived
from it, including `sessions.csv` / `sessions.json`, `commands.jsonl` (and their `.gz`
compressed forms),
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

Client IP addresses in the commands files (`commands.jsonl`, and the
`commands/` Parquet files on data.vtyagi.dev) are anonymized (salted hash).
The sessions files carry the real `client_ip`, by decision: every connection
to an SSH or telnet honeypot is unsolicited, nearly all of it from bots, and
the source address is the attack infrastructure researchers need for
blocklists and attribution. Many of those addresses are compromised devices
on residential networks, so they identify a hijacked device, not its owner's
intent. The mirage-crawl HTTP dataset hashes every IP with the same salt,
because its documentation site is also browsed by people.

Users of the dataset must not attempt to re-identify individuals or deanonymize
source addresses beyond what the project already publishes.
