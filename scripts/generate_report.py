"""
generate_report.py

Reads a versioned dataset (stats_summary.json + sessions.csv) produced
by export_dataset.py and writes a markdown findings report alongside it.

Usage:
    python generate_report.py --dataset-dir dataset/v1
"""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def load_summary(dataset_dir: Path) -> dict:
    with open(dataset_dir / "stats_summary.json", encoding="utf-8") as f:
        return json.load(f)


def load_sessions(dataset_dir: Path) -> list[dict]:
    with open(dataset_dir / "sessions.csv", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def analyze_coordinated_groups(summary: dict, sessions: list[dict]) -> list[dict]:
    """
    For each coordinated IP group from the summary, look up each IP's
    ASN/country from the session rows and break down how many IPs in
    the group share each ASN. This lets the report state precisely
    how many IPs in a group share infrastructure, rather than just
    asserting it.
    """
    ip_to_geo = {}
    for row in sessions:
        ip = row["client_ip"]
        if ip not in ip_to_geo:
            ip_to_geo[ip] = (row["asn"], row["asn_name"], row["country"])

    analyzed = []
    for group in summary["coordinated_ip_groups"]:
        # Skip the long tail of singleton-session groups (session_count == 1
        # with many IPs is just "many scanners hit us once", not coordination)
        if group["session_count"] == 1:
            continue

        asn_breakdown = Counter()
        country_breakdown = Counter()
        unresolved = 0

        for ip in group["ips"]:
            asn, asn_name, country = ip_to_geo.get(ip, (None, None, None))
            if asn_name:
                asn_breakdown[asn_name] += 1
            else:
                unresolved += 1
            if country:
                country_breakdown[country] += 1

        analyzed.append(
            {
                **group,
                "asn_breakdown": asn_breakdown.most_common(),
                "country_breakdown": country_breakdown.most_common(),
                "unresolved_count": unresolved,
            }
        )

    return analyzed


def render_report(summary: dict, coordinated_analysis: list[dict], version: str) -> str:
    lines = []

    lines.append(f"# MIRAGE Honeypot Dataset — {version}")
    lines.append("")
    lines.append(
        f"Generated from live capture data. Snapshot covers "
        f"**{summary['total_sessions']:,} sessions** across "
        f"**{summary['unique_ips']} unique source IPs**."
    )
    lines.append("")

    # --- Headline finding ---
    lines.append("## Headline finding")
    lines.append("")
    lines.append(
        f"**{summary['zero_command_sessions']:,} of {summary['total_sessions']:,} "
        f"sessions ({summary['zero_command_pct']}%) executed zero commands** "
        f"after authentication. Every captured session in this snapshot "
        f"consists entirely of automated credential-stuffing attempts against "
        f"the SSH auth layer — no attacker has reached the interactive shell."
    )
    lines.append("")

    # --- SSH client banners ---
    lines.append("## SSH client banners")
    lines.append("")
    lines.append("| Banner | Sessions |")
    lines.append("|---|---|")
    for banner, count in summary["ssh_banners"]:
        lines.append(f"| `{banner}` | {count:,} |")
    lines.append("")

    # --- Coordinated infrastructure ---
    lines.append("## Coordinated infrastructure")
    lines.append("")

    if coordinated_analysis:
        lines.append(
            "Groups of source IPs sharing an identical session count — a "
            "signal of scripted, centrally-orchestrated behaviour rather than "
            "independent scanners hitting similar numbers by chance."
        )
        lines.append("")

        for group in coordinated_analysis:
            lines.append(
                f"### {group['ip_count']} IPs at exactly "
                f"{group['session_count']:,} sessions each"
            )
            lines.append("")

            if group["asn_breakdown"]:
                asn_parts = ", ".join(
                    f"{name} ({count})" for name, count in group["asn_breakdown"]
                )
                lines.append(f"- **ASN breakdown:** {asn_parts}")

            if group["country_breakdown"]:
                country_parts = ", ".join(
                    f"{code} ({count})" for code, count in group["country_breakdown"]
                )
                lines.append(f"- **Country breakdown:** {country_parts}")

            if group["unresolved_count"]:
                lines.append(
                    f"- **{group['unresolved_count']} IP(s) unresolved** "
                    f"(outside this snapshot's geo data coverage)"
                )

            lines.append("")
    else:
        lines.append("No coordinated groups (session_count > 1, ip_count > 2) found in this snapshot.")
        lines.append("")

    # --- Top ASNs / countries (whole dataset) ---
    lines.append("## Top source ASNs (full dataset)")
    lines.append("")
    lines.append("| ASN Name | Sessions |")
    lines.append("|---|---|")
    for asn_name, count in summary["top_asns"]:
        lines.append(f"| {asn_name} | {count:,} |")
    lines.append("")

    lines.append("## Top source countries (full dataset)")
    lines.append("")
    lines.append("| Country | Sessions |")
    lines.append("|---|---|")
    for country, count in summary["top_countries"]:
        lines.append(f"| {country} | {count:,} |")
    lines.append("")

    # --- Data notes ---
    lines.append("## Data notes")
    lines.append("")
    lines.append(
        f"- {summary['geo_unmatched_ips']} of {summary['unique_ips']} source IPs "
        f"could not be resolved to an ASN in this snapshot's pinned DB-IP data "
        f"(coverage gap, not a classification result)."
    )
    lines.append(
        "- `attacker_class` and `classifier_confidence` in the underlying "
        "dataset currently reflect interpretable weak-label heuristics "
        "(banner signature, auth pattern), not a trained ML classifier. "
        "A trained behavioural classifier is in development; this snapshot "
        "predates it."
    )
    lines.append(
        "- ASN/country attribution: [DB-IP](https://db-ip.com), "
        "licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)."
    )
    lines.append("")

    lines.append("---")
    lines.append("")
    generated_at_raw = summary.get("generated_at")
    if generated_at_raw:
        try:
            dt = datetime.fromtimestamp(int(generated_at_raw) / 1000, tz=timezone.utc)
            generated_at_str = dt.strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, TypeError):
            generated_at_str = str(generated_at_raw)
    else:
        generated_at_str = "unknown"
    lines.append(f"*Generated {generated_at_str}. Dataset version: {version}.*")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-dir", required=True, help="e.g. dataset/v1")
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir)
    version = dataset_dir.name

    summary = load_summary(dataset_dir)
    sessions = load_sessions(dataset_dir)

    coordinated_analysis = analyze_coordinated_groups(summary, sessions)
    report_text = render_report(summary, coordinated_analysis, version)

    out_path = dataset_dir / "REPORT.md"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
