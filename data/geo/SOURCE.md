# Geo Data Source

## Source
DB-IP ASN Lite, https://db-ip.com/db/download/ip-to-asn-lite

Free tier, no account or license key required. Licensed under
Creative Commons Attribution 4.0 International (CC BY 4.0):
https://creativecommons.org/licenses/by/4.0/

Per the license, any public use of this data (including the published
MIRAGE dataset and report) must retain attribution to DB-IP. The
weekly report generator includes this in its output footer.

## File
`dbip-asn-lite.csv` — downloaded 2026-06-30, sourced from the
2026-06 monthly release:
https://download.db-ip.com/free/dbip-asn-lite-2026-06.csv.gz

## Format
One row per IP range:
range_start,range_end,asn,asn_name[,country]

range_start / range_end are plain dotted-quad IPv4 addresses (not
CIDR notation). Parsed and range-searched via scripts/geo_lookup.py.

## Refresh policy
Pinned, not auto-updated. ASN ownership data is stable enough that
this doesn't need to refresh on every export run. Re-download and
re-commit every 2-3 months, or sooner if geo_unmatched_ips in a
stats_summary.json starts climbing (a sign the snapshot is going
stale as new IP ranges get allocated).

To refresh:
    curl -L -o data/geo/dbip-asn-lite.csv.gz \
        https://download.db-ip.com/free/dbip-asn-lite-<YYYY>-<MM>.csv.gz
    gunzip data/geo/dbip-asn-lite.csv.gz

Update the "File" section above with the new download date and
source month after refreshing.
