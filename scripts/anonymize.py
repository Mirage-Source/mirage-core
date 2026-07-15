"""
anonymize.py

Shared anonymization helpers for the dataset export scripts
(export_dataset.py, export_commands_dataset.py). Kept in one place so both
scripts hash IPs the same way -- a consumer joining the two exported files
by client_ip needs identical salted hashes on both sides.
"""

import hashlib
import hmac


def anonymize_ip(ip: str, salt: str) -> str:
    digest = hmac.new(salt.encode(), ip.encode(), hashlib.sha256).hexdigest()[:16]
    return f"anon_{digest}"
