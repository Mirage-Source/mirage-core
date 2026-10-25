"""
anonymize.py

Shared anonymization helpers for the dataset export scripts
(export_dataset.py, export_commands_dataset.py). Kept in one place so both
scripts hash IPs the same way -- a consumer joining the two exported files
by client_ip needs identical salted hashes on both sides.
"""

import hashlib
import hmac
import re


def anonymize_ip(ip: str, salt: str) -> str:
    digest = hmac.new(salt.encode(), ip.encode(), hashlib.sha256).hexdigest()[:16]
    return f"anon_{digest}"


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
