"""
real_db.py

Pulls sessions directly from a Postgres backup/restore of the MIRAGE
production database. mirage-core has no live API once the sensor is offline
(see DECISIONS.md, 2026-08-26), so this bypasses the REST-API-based export
scripts under scripts/ (which need a running mirage-api) and talks to
Postgres the same way bridge/db.py does.

Two CLI entry points (registered in pyproject.toml):

  mirage-reid-campaign  -- run the structural-signature campaign test against
                            the live DB and write a summary JSON.
  mirage-reid-export    -- pull every session, attach identity/toolkit labels,
                            and write the real IdentityCorpus JSONL that
                            mirage.reid.train's real-data path consumes.

Not exercised by the pytest suite (no Postgres in CI for this path); validate
manually against a restored backup before trusting its output.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from ..data.schema import AuthAttempt, Command, Session
from .campaign import CampaignResult, detect_campaign, divisibility_candidates
from .real_data import build_real_identity_corpus, save_real_identity_corpus

__all__ = [
    "RealDBConfig",
    "connect",
    "fetch_session_counts",
    "fetch_credential_pair_sets",
    "detect_campaign_from_db",
    "fetch_real_sessions",
    "main_detect_campaign",
    "main_export_corpus",
]


@dataclass
class RealDBConfig:
    """Postgres connection settings, sharing bridge/config.py's env var names."""

    host: str = "localhost"
    port: str = "5432"
    user: str = "mirage"
    password: str = "mirage"
    dbname: str = "mirage"

    def dsn(self) -> str:
        return (
            f"host={self.host} port={self.port} user={self.user} "
            f"password={self.password} dbname={self.dbname} sslmode=disable"
        )

    @classmethod
    def from_env(cls) -> "RealDBConfig":
        return cls(
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432"),
            user=os.getenv("DB_USER", "mirage"),
            password=os.getenv("DB_PASSWORD", "mirage"),
            dbname=os.getenv("DB_NAME", "mirage"),
        )


def connect(config: RealDBConfig):
    """Open a psycopg2 connection. Imports psycopg2 lazily so importing this
    module doesn't force the ``real-data`` extra on callers who only need the
    DB-independent parts of the re-ID pipeline."""
    import psycopg2

    return psycopg2.connect(config.dsn())


def fetch_session_counts(conn) -> dict[str, int]:
    """``{client_ip: session_count}`` for every non-empty source address.

    Empty ``client_ip`` (1,189 sessions in the paper's snapshot -- TCP
    connections that closed before the SSH handshake completed) is excluded
    at the SQL level, matching the preprint's own per-address exclusion
    (Section IV-C).
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT client_ip, count(*) FROM sessions WHERE client_ip <> '' GROUP BY client_ip"
        )
        return {ip: int(n) for ip, n in cur.fetchall()}


def fetch_credential_pair_sets(
    conn, ips: Iterable[str]
) -> dict[str, frozenset[tuple[str, str]]]:
    """``{ip: frozenset of (username, credential) pairs}`` for the given addresses."""
    ip_list = list(ips)
    if not ip_list:
        return {}
    pairs: dict[str, set[tuple[str, str]]] = {ip: set() for ip in ip_list}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.client_ip, a.username, a.credential
            FROM auth_attempts a
            JOIN sessions s ON s.session_id = a.session_id
            WHERE s.client_ip = ANY(%s)
            """,
            (ip_list,),
        )
        for ip, username, credential in cur.fetchall():
            pairs[ip].add((username, credential))
    return {ip: frozenset(p) for ip, p in pairs.items()}


def detect_campaign_from_db(conn, wordlist_len: int = 761) -> CampaignResult:
    """Run :func:`mirage.reid.campaign.detect_campaign` against the live DB."""
    counts = fetch_session_counts(conn)
    candidates = divisibility_candidates(counts, wordlist_len)
    pair_sets = fetch_credential_pair_sets(conn, candidates.keys())
    return detect_campaign(counts, pair_sets, wordlist_len)


def _decode_raw(raw_input_b64: str) -> str:
    return base64.b64decode(raw_input_b64).decode("utf-8", errors="replace")


def fetch_real_sessions(conn, ips: Iterable[str] | None = None) -> list[Session]:
    """Pull every session (with ordered commands and auth attempts) for
    ``ips``, or every non-empty-``client_ip`` session if ``ips`` is ``None``.

    Three round trips (sessions, then commands, then auth_attempts, each keyed
    by the resulting session ids) rather than a join -- the 154,806-session
    corpus is small enough that this is simpler than streaming a joined result
    set, and it keeps sessions with neither commands nor auth attempts trivial
    to construct.
    """
    where = "client_ip <> ''"
    params: tuple = ()
    if ips is not None:
        ip_list = list(ips)
        if not ip_list:
            return []
        where += " AND client_ip = ANY(%s)"
        params = (ip_list,)

    sessions: dict[str, Session] = {}
    with conn.cursor() as cur:
        cur.execute(
            "SELECT session_id, client_ip, start_ms, duration_ms, ssh_client_banner "
            f"FROM sessions WHERE {where}",
            params,
        )
        for session_id, client_ip, start_ms, duration_ms, banner in cur.fetchall():
            start = datetime.fromtimestamp(start_ms / 1000.0, tz=timezone.utc)
            sessions[session_id] = Session(
                session_id=session_id,
                ip=client_ip,
                start_time=start,
                duration_ms=int(duration_ms) if duration_ms is not None else None,
                ssh_client_banner=banner or "",
            )

    if not sessions:
        return []

    session_ids = list(sessions.keys())

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT session_id, timestamp_ms, raw_input_b64
            FROM commands
            WHERE session_id = ANY(%s)
            ORDER BY session_id, sequence_number
            """,
            (session_ids,),
        )
        for session_id, timestamp_ms, raw_input_b64 in cur.fetchall():
            session = sessions[session_id]
            start_ms = int(session.start_time.timestamp() * 1000)
            session.commands.append(
                Command(
                    timestamp=datetime.fromtimestamp(timestamp_ms / 1000.0, tz=timezone.utc),
                    raw=_decode_raw(raw_input_b64),
                    ms_offset=int(timestamp_ms) - start_ms,
                )
            )

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT session_id, username, credential
            FROM auth_attempts
            WHERE session_id = ANY(%s)
            ORDER BY session_id, timestamp_ms
            """,
            (session_ids,),
        )
        for session_id, username, credential in cur.fetchall():
            sessions[session_id].auth_attempts.append(
                AuthAttempt(username=username, credential=credential)
            )

    return list(sessions.values())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main_detect_campaign(argv: list[str] | None = None) -> CampaignResult:
    """``mirage-reid-campaign`` -- run the structural-signature test, print +
    persist a summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wordlist-len", type=int, default=761)
    parser.add_argument("--out", default="data/labels/campaign_membership.json")
    args = parser.parse_args(argv)

    config = RealDBConfig.from_env()
    conn = connect(config)
    try:
        result = detect_campaign_from_db(conn, wordlist_len=args.wordlist_len)
    finally:
        conn.close()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tier_summary = {
        str(tier): {"ips": n_ips, "sessions": n_sessions}
        for tier, (n_ips, n_sessions) in sorted(result.tier_summary().items())
    }
    payload = {
        "wordlist_len": args.wordlist_len,
        "n_ips": len(result.members),
        "total_sessions": result.total_sessions,
        "tier_summary": tier_summary,
        "members": [
            {"ip": m.ip, "tier": m.tier, "session_count": m.session_count}
            for m in result.members
        ],
        "excluded_coincidental_divisors": result.excluded,
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"[campaign] {len(result.members)} ips, {result.total_sessions} sessions -> {out}")
    for tier, (n_ips, n_sessions) in sorted(result.tier_summary().items()):
        print(f"  tier {tier}x: {n_ips} ips, {n_sessions} sessions")
    if result.excluded:
        print(f"  excluded (coincidental divisor, credential set mismatch): {result.excluded}")
    return result


def main_export_corpus(argv: list[str] | None = None) -> None:
    """``mirage-reid-export`` -- pull every session, label it, write the real
    ``IdentityCorpus`` JSONL that ``mirage.reid.train``'s real-data path reads."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wordlist-len", type=int, default=761)
    parser.add_argument("--min-sessions-per-identity", type=int, default=1)
    parser.add_argument("--out", default="data/reid/real_corpus.jsonl")
    args = parser.parse_args(argv)

    config = RealDBConfig.from_env()
    conn = connect(config)
    try:
        campaign = detect_campaign_from_db(conn, wordlist_len=args.wordlist_len)
        sessions = fetch_real_sessions(conn)
    finally:
        conn.close()

    corpus = build_real_identity_corpus(
        sessions, campaign, min_sessions_per_identity=args.min_sessions_per_identity
    )
    save_real_identity_corpus(corpus, args.out)
    print(
        f"[export] {len(corpus)} sessions, {corpus.n_identities} identities, "
        f"{len(campaign.members)} campaign-confirmed addresses -> {args.out}"
    )


if __name__ == "__main__":  # pragma: no cover
    main_export_corpus()
