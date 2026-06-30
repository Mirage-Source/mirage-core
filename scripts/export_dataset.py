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
from collections import Counter, defaultdict
from pathlib import Path

import requests

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


def enrich_sessions(sessions: list[dict], geo: GeoLookup) -> tuple[list[dict], int]:
    enriched = []
    unmatched_count = 0

    for s in sessions:
        result = geo.lookup(s["client_ip"])

        if not result.matched:
            unmatched_count += 1

        row = dict(s)
        row["asn"] = result.asn
        row["asn_name"] = result.asn_name
        row["country"] = result.country
        # mitre_techniques arrives as a list, flatten for CSV row,
        # JSON output keeps it as a real list separately.
        row["mitre_techniques"] = ";".join(s.get("mitre_techniques") or [])
        enriched.append(row)

    return enriched, unmatched_count


def write_csv(rows: list[dict], path: Path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(sessions_raw: list[dict], geo_lookups: dict[str, dict], path: Path):
    # JSON keeps mitre_techniques as a real array and nests geo info,
    # rather than flattening like the CSV does — meant for programmatic
    # consumption (pandas, R, jq) where structure is preferred over flat rows.
    out = []
    for s in sessions_raw:
        geo = geo_lookups[s["client_ip"]]
        out.append(
            {
                **s,
                "asn": geo["asn"],
                "asn_name": geo["asn_name"],
                "country": geo["country"],
            }
        )

    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def compute_summary(rows: list[dict], unmatched_geo_count: int) -> dict:
    total = len(rows)
    banner_counts = Counter(r["ssh_client_banner"] for r in rows)
    country_counts = Counter(r["country"] for r in rows if r["country"])
    asn_counts = Counter(r["asn_name"] for r in rows if r["asn_name"])

    # Sessions with zero commands executed — the headline finding.
    zero_command_sessions = sum(1 for r in rows if r["command_count"] == 0)

    # Coordinated IP groups: same logic as the Go /api/stats query —
    # group by session count per IP, flag groups with >2 IPs sharing
    # an identical count (signal of scripted/orchestrated behaviour).
    ip_session_counts: dict[str, int] = defaultdict(int)
    for r in rows:
        ip_session_counts[r["client_ip"]] += 1

    count_to_ips: dict[int, list[str]] = defaultdict(list)
    for ip, count in ip_session_counts.items():
        count_to_ips[count].append(ip)

    coordinated_groups = [
        {"session_count": count, "ip_count": len(ips), "ips": sorted(ips)}
        for count, ips in count_to_ips.items()
        if len(ips) > 2
    ]
    coordinated_groups.sort(key=lambda g: g["session_count"], reverse=True)

    return {
        "total_sessions": total,
        "unique_ips": len(ip_session_counts),
        "zero_command_sessions": zero_command_sessions,
        "zero_command_pct": round(100 * zero_command_sessions / total, 2) if total else 0,
        "geo_unmatched_ips": unmatched_geo_count,
        "ssh_banners": banner_counts.most_common(10),
        "top_countries": country_counts.most_common(10),
        "top_asns": asn_counts.most_common(10),
        "coordinated_ip_groups": coordinated_groups,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--geo-asn-csv", required=True)
    parser.add_argument("--geo-country-csv", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--version", required=True, help="e.g. v12")
    args = parser.parse_args()

    print(f"Fetching export from {args.api_url}/api/export ...", file=sys.stderr)
    export = fetch_export(args.api_url, args.api_key)
    sessions = export["sessions"]
    print(f"Got {len(sessions)} sessions (generated_at={export['generated_at']})", file=sys.stderr)

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

    enriched_rows, _ = enrich_sessions(sessions, geo)

    out_dir = Path(args.out_dir) / args.version
    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(enriched_rows, out_dir / "sessions.csv")
    write_json(sessions, geo_lookups, out_dir / "sessions.json")

    summary = compute_summary(enriched_rows, unmatched_count)
    summary["generated_at"] = export["generated_at"]
    summary["version"] = args.version

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
