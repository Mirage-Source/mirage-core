"""
export_dataset.py

Pulls the full session export from MIRAGE's /api/export endpoint,
enriches each session with ASN/country via the pinned DB-IP ASN-lite
snapshot, and writes a versioned dataset (CSV + JSON) plus a
stats_summary.json used by generate_report.py.

Usage:
    python export_dataset.py --api-url  \
                              --api-key $API_KEY \
                              --geo-asn-csv data/geo/dbip-asn-lite.csv \
                              --geo-country-csv data/geo/dbip-country-lite.csv \
                              --out-dir dataset \
                              --version v12
"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import requests

from anonymize import anonymize_ip
from geo_lookup import GeoLookup


FIELDNAMES = [
    "session_id",
    "node_id",
    "client_ip",
    "asn",
    "asn_name",
    "country",
    "ssh_client_banner",
    "start_ms",
    "end_ms",
    "duration_ms",
    "outcome",
    "command_count",
    "bait_hit_count",
    "attacker_class",
    "classifier_confidence",
    "cluster_id",
    "mitre_techniques",
    "auth_attempt_count",
    "unique_usernames_tried",
    "top_username",
]


def fetch_export(api_url: str, api_key: str) -> dict:
    resp = requests.get(
        f"{api_url.rstrip('/')}/api/export",
        headers={"X-API-Key": api_key},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_stats(api_url: str, api_key: str) -> dict:
    resp = requests.get(
        f"{api_url.rstrip('/')}/api/stats",
        headers={"X-API-Key": api_key},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def enrich_sessions(
    sessions: list[dict],
    geo_lookups: dict[str, dict],
    ip_salt: str | None = None,
) -> list[dict]:
    """Attach the already-resolved (deduplicated) per-IP geo data to each row."""
    enriched = []

    for s in sessions:
        # Geo/ASN lookup must happen against the real IP; anonymization
        # only replaces the identifier afterward.
        geo = geo_lookups[s["client_ip"]]

        row = dict(s)
        row["asn"] = geo["asn"]
        row["asn_name"] = geo["asn_name"]
        row["country"] = geo["country"]
        if ip_salt is not None:
            row["client_ip"] = anonymize_ip(s["client_ip"], ip_salt)
        # mitre_techniques arrives as a list, flatten for CSV row,
        # JSON output keeps it as a real list separately.
        row["mitre_techniques"] = ";".join(s.get("mitre_techniques") or [])
        enriched.append(row)

    return enriched


def write_csv(rows: list[dict], path: Path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(sessions_raw: list[dict], enriched_rows: list[dict], path: Path):
    # JSON keeps mitre_techniques as a real array and nests geo info,
    # rather than flattening like the CSV does — meant for programmatic
    # consumption (pandas, R, jq) where structure is preferred over flat rows.
    # client_ip/asn/country come from the enriched row (not re-derived from
    # sessions_raw) so an anonymized export can't leak the real IP here
    # while the CSV output stays anonymized.
    out = []
    for s, row in zip(sessions_raw, enriched_rows):
        out.append(
            {
                **s,
                "client_ip": row["client_ip"],
                "asn": row["asn"],
                "asn_name": row["asn_name"],
                "country": row["country"],
            }
        )

    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def compute_summary(rows: list[dict], unmatched_geo_count: int, coordinated_ip_groups: list[dict]) -> dict:
    total = len(rows)
    banner_counts = Counter(r["ssh_client_banner"] for r in rows)
    country_counts = Counter(r["country"] for r in rows if r["country"])
    asn_counts = Counter(r["asn_name"] for r in rows if r["asn_name"])

    # Sessions with zero commands executed — the headline finding.
    zero_command_sessions = sum(1 for r in rows if r["command_count"] == 0)

    return {
        "total_sessions": total,
        "unique_ips": len(set(r["client_ip"] for r in rows)),
        "zero_command_sessions": zero_command_sessions,
        "zero_command_pct": round(100 * zero_command_sessions / total, 2) if total else 0,
        "geo_unmatched_ips": unmatched_geo_count,
        "ssh_banners": banner_counts.most_common(10),
        "top_countries": country_counts.most_common(10),
        "top_asns": asn_counts.most_common(10),
        # Sourced from /api/stats -- same shared-credential + shared-banner +
        # 5-minute-window heuristic the live dashboard uses, not an
        # independently (and differently) computed one. See internal/store/
        # read.go's coordinated-IP query for the real definition.
        "coordinated_ip_groups": coordinated_ip_groups,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--geo-asn-csv", required=True)
    parser.add_argument("--geo-country-csv", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--version", required=True, help="e.g. g2-v12")
    parser.add_argument(
        "--sensor-generation",
        help=(
            "identifier for the sensor deployment this data came from, e.g. "
            "'g2'. Recorded in stats_summary.json so versions collected by "
            "different sensors are not silently joined."
        ),
    )
    # Off by default: current exports use the real client_ip.
    parser.add_argument(
        "--anonymize-ips",
        action="store_true",
        help="replace client_ip with a salted HMAC in exported output",
    )
    parser.add_argument(
        "--ip-salt",
        help="HMAC key for --anonymize-ips (required if that flag is set)",
    )
    args = parser.parse_args()

    if args.anonymize_ips and not args.ip_salt:
        parser.error("--ip-salt is required when --anonymize-ips is set")

    print(f"Fetching export from {args.api_url}/api/export ...", file=sys.stderr)
    export = fetch_export(args.api_url, args.api_key)
    sessions = export["sessions"]
    print(f"Got {len(sessions)} sessions (generated_at={export['generated_at']})", file=sys.stderr)

    print(f"Fetching coordinated-IP groups from {args.api_url}/api/stats ...", file=sys.stderr)
    stats = fetch_stats(args.api_url, args.api_key)
    coordinated_ip_groups = stats.get("coordinated_ips", [])

    print(f"Loading geo data from {args.geo_asn_csv} and {args.geo_country_csv} ...", file=sys.stderr)
    geo = GeoLookup(args.geo_asn_csv, args.geo_country_csv)

    print("Resolving ASN/country per session ...", file=sys.stderr)
    geo_lookups = {}
    unmatched_count = 0
    for s in sessions:
        if s["client_ip"] not in geo_lookups:
            result = geo.lookup(s["client_ip"])
            geo_lookups[s["client_ip"]] = {
                "asn": result.asn,
                "asn_name": result.asn_name,
                "country": result.country,
            }
            if not result.matched:
                unmatched_count += 1

    ip_salt = args.ip_salt if args.anonymize_ips else None
    enriched_rows = enrich_sessions(sessions, geo_lookups, ip_salt)

    out_dir = Path(args.out_dir) / args.version
    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(enriched_rows, out_dir / "sessions.csv")
    write_json(sessions, enriched_rows, out_dir / "sessions.json")

    summary = compute_summary(enriched_rows, unmatched_count, coordinated_ip_groups)
    summary["generated_at"] = export["generated_at"]
    summary["version"] = args.version
    summary["ip_anonymized"] = args.anonymize_ips
    if args.sensor_generation:
        summary["sensor_generation"] = args.sensor_generation

    with open(out_dir / "stats_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Wrote dataset to {out_dir}/", file=sys.stderr)
    print(
        f"  {summary['total_sessions']} sessions, "
        f"{summary['unique_ips']} unique IPs, "
        f"{unmatched_count} unmatched in geo lookup",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
