from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from ..data.schema import Session
from .campaign import CampaignResult
from .data import IdentityCorpus
from .loss import UNKNOWN_TOOLKIT

__all__ = [
    "toolkit_label_for",
    "build_real_identity_corpus",
    "save_real_identity_corpus",
    "load_real_identity_corpus",
]


def toolkit_label_for(ip: str, campaign: CampaignResult) -> str:
    """Coarse toolkit label for an address: its campaign tier if confirmed, else
    :data:`~mirage.reid.loss.UNKNOWN_TOOLKIT`.

    Deliberately linear-scan (``campaign.members`` tops out at 50, per the
    preprint) rather than requiring the caller to pre-index -- this is called
    once per address while building a corpus, not per session.
    """
    for m in campaign.members:
        if m.ip == ip:
            return f"campaign_tier{m.tier}"
    return UNKNOWN_TOOLKIT


def build_real_identity_corpus(
    sessions: Sequence[Session],
    campaign: CampaignResult,
    min_sessions_per_identity: int = 1,
) -> IdentityCorpus:
    """Assemble an :class:`~mirage.reid.data.IdentityCorpus` from real sessions.

    Identity = source address: verified ground truth for every session (a row-
    level fact, not an inference). Toolkit = confirmed campaign-tier
    membership, or the ``UNKNOWN_TOOLKIT`` placeholder otherwise (see
    :mod:`mirage.reid.campaign`) -- never an asserted identity claim beyond
    what the structural-signature test actually verified.

    Args:
        sessions: Real sessions. Every ``session.ip`` must be non-empty; the
            preprint excludes empty-``client_ip`` rows from all per-address
            analysis (Section IV-C, the TCP-only connections that never
            completed a handshake) and callers should filter those out before
            reaching this function.
        campaign: The confirmed campaign membership (see
            :func:`mirage.reid.campaign.detect_campaign`).
        min_sessions_per_identity: Drop addresses with fewer sessions than
            this. Default ``1`` keeps every address (an address with exactly
            one session still trains, via augmentation-only positives — see
            :mod:`mirage.reid.pk_sampler`); raise it to require a real (non-
            augmented) positive pair per identity.

    Returns:
        An :class:`IdentityCorpus`, the same container the synthetic Phase-3
        pipeline already consumes. ``profiles`` is left empty since there is no
        latent synthetic profile behind real data.

    Raises:
        ValueError: If any session has an empty ``ip``.
    """
    by_ip: dict[str, list[Session]] = {}
    for s in sessions:
        if not s.ip:
            raise ValueError(
                f"session {s.session_id!r} has an empty ip; filter it out before "
                "building a real identity corpus"
            )
        by_ip.setdefault(s.ip, []).append(s)

    kept_sessions: list[Session] = []
    identity_labels: list[str] = []
    toolkit_labels: list[str] = []
    for ip, ip_sessions in by_ip.items():
        if len(ip_sessions) < min_sessions_per_identity:
            continue
        toolkit = toolkit_label_for(ip, campaign)
        for s in ip_sessions:
            kept_sessions.append(s)
            identity_labels.append(ip)
            toolkit_labels.append(toolkit)

    return IdentityCorpus(
        sessions=kept_sessions,
        identity_labels=identity_labels,
        toolkit_labels=toolkit_labels,
    )


def save_real_identity_corpus(corpus: IdentityCorpus, path: str | Path) -> None:
    """Serialize a real :class:`IdentityCorpus` to JSONL: one row per session.

    Decouples the one-time DB pull (:mod:`mirage.reid.real_db`, requires a
    Postgres connection) from training (requires only this file) -- the same
    "export once, train many times" shape as the rest of the repo's dataset
    export scripts.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for session, identity, toolkit in zip(
            corpus.sessions, corpus.identity_labels, corpus.toolkit_labels
        ):
            row = {"identity": identity, "toolkit": toolkit, "session": session.to_dict()}
            f.write(json.dumps(row) + "\n")


def load_real_identity_corpus(path: str | Path) -> IdentityCorpus:
    """Load an :class:`IdentityCorpus` written by :func:`save_real_identity_corpus`."""
    sessions: list[Session] = []
    identity_labels: list[str] = []
    toolkit_labels: list[str] = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            sessions.append(Session.from_dict(row["session"]))
            identity_labels.append(row["identity"])
            toolkit_labels.append(row["toolkit"])
    return IdentityCorpus(
        sessions=sessions, identity_labels=identity_labels, toolkit_labels=toolkit_labels
    )
