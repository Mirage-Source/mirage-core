"""
export_commands_dataset.py

Pulls the full commands export from MIRAGE's /api/export/commands endpoint
(paginated via ?after=/?limit=) and writes it as commands.jsonl -- one JSON
object per line, the standard shape for LLM training corpora -- into the
same versioned dataset directory export_dataset.py writes sessions.csv/
sessions.json into.

Unlike export_dataset.py, IP anonymization here defaults to ON: this file
is built specifically to be handed to third parties for LLM training, so
--ip-salt is required unless --no-anonymize-ips is passed explicitly.

Usage:
    python export_commands_dataset.py --api-url  \
                                       --api-key $API_KEY \
                                       --out-dir dataset \
                                       --version v12 \
                                       --ip-salt $IP_SALT
"""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

from anonymize import anonymize_ip

PAGE_LIMIT = 5000

# Best-effort redaction of secret-shaped substrings that might appear in
# attacker-typed command text or an echoed response (e.g. `echo` args, or a
# command copy-pasting the attacker's own tooling). This is NOT a guarantee
# -- free-text scrubbing can't be perfect -- it's a defense-in-depth pass on
# top of the fact that almost all sensitive-looking content in this dataset
# is MIRAGE's own clearly-fake planted bait (see internal/shell/fs.go),
# which is intentionally left untouched since it isn't real.
_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*\S+"), "aws_secret_access_key=[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b[a-f0-9]{32,64}\b", re.IGNORECASE), "[REDACTED_TOKEN]"),
]


def scrub_secrets(text: str | None) -> str | None:
    if not text:
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def fetch_all_commands(api_url: str, api_key: str) -> list[dict]:
    commands = []
    after = None
    page = 0
    while True:
        params = {"limit": PAGE_LIMIT}
        if after:
            params["after"] = after
        resp = requests.get(
            f"{api_url.rstrip('/')}/api/export/commands",
            headers={"X-API-Key": api_key},
            params=params,
            timeout=60,
        )
        resp.raise_for_status()
        body = resp.json()

        page += 1
        commands.extend(body["commands"])
        print(
            f"  page {page}: +{body['command_count']} commands (total {len(commands)})",
            file=sys.stderr,
        )

        after = body.get("next_cursor")
        if not after:
            break

    return commands


def anonymize_and_scrub(commands: list[dict], ip_salt: str | None) -> list[dict]:
    out = []
    for c in commands:
        row = dict(c)
        if ip_salt is not None:
            row["client_ip"] = anonymize_ip(c["client_ip"], ip_salt)
        row["raw_command"] = scrub_secrets(row.get("raw_command"))
        row["response"] = scrub_secrets(row.get("response"))
        out.append(row)
    return out


def write_jsonl(rows: list[dict], path: Path):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--version", required=True, help="e.g. v12")
    parser.add_argument(
        "--ip-salt",
        help="HMAC key used to anonymize client_ip (required unless --no-anonymize-ips)",
    )
    parser.add_argument(
        "--no-anonymize-ips",
        action="store_true",
        help="ship real client_ip values instead of a salted HMAC (off by default, unlike export_dataset.py)",
    )
    args = parser.parse_args()

    if not args.no_anonymize_ips and not args.ip_salt:
        parser.error("--ip-salt is required unless --no-anonymize-ips is set")

    print(f"Fetching commands export from {args.api_url}/api/export/commands ...", file=sys.stderr)
    commands = fetch_all_commands(args.api_url, args.api_key)
    print(f"Got {len(commands)} commands", file=sys.stderr)

    ip_salt = None if args.no_anonymize_ips else args.ip_salt
    rows = anonymize_and_scrub(commands, ip_salt)

    out_dir = Path(args.out_dir) / args.version
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / "commands.jsonl"
    write_jsonl(rows, out_path)

    print(f"Wrote {len(rows)} commands to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
