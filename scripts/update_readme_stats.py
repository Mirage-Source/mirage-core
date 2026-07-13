#!/usr/bin/env python3
"""Regenerate the Live findings block in README.md from a stats.json snapshot."""
import argparse
import json
import re

START = "<!-- STATS:START -->"
END = "<!-- STATS:END -->"


def render(stats: dict) -> str:
    total = stats["total_sessions"]
    ips = stats["unique_ips"]
    last_24h = stats.get("sessions_last_24h", 0)
    generated = stats.get("generated_at", "")

    top_creds = stats.get("top_credentials") or []
    coord = stats.get("coordinated_ips") or []

    lines = [
        START,
        f"- **{total:,} sessions** captured from **{ips:,} unique source IPs** "
        f"({last_24h:,} in the last 24h)",
    ]

    if top_creds:
        top = top_creds[0]
        lines.append(
            f"- Most repeated credential pair: `{top.get('username')}` / "
            f"`{top.get('password')}` ({top.get('count', 0):,} attempts)"
        )

    if coord:
        distinct_ips = {ip for group in coord for ip in group.get("ips", [])}
        lines.append(
            f"- **{len(coord)} coordinated credential-stuffing windows** identified, "
            f"across {len(distinct_ips)} distinct IPs sharing the same credential and "
            f"SSH client banner within a 5-minute window"
        )

    if generated:
        lines.append(f"\n_Last updated automatically: {generated}_")

    lines.append(END)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stats", required=True, help="path to stats.json")
    parser.add_argument("--readme", default="README.md")
    args = parser.parse_args()

    with open(args.stats) as f:
        stats = json.load(f)

    with open(args.readme) as f:
        content = f.read()

    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(content):
        raise SystemExit(f"{args.readme} is missing {START}/{END} markers")

    content = pattern.sub(lambda _: render(stats), content, count=1)

    with open(args.readme, "w") as f:
        f.write(content)


if __name__ == "__main__":
    main()
