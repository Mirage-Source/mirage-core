"""Offered public keys must not move password-derived features or MITRE hits.

Sensors record rejected public-key attempts alongside passwords. Every
consumer below was defined over password attempts only, so adding keys to a
session must leave its output unchanged.
"""
from __future__ import annotations

import copy
import random

from mirage.intel.features import extract_features
from mirage.intel.ingest import parse_session_document
from mirage.intel.mitre import map_mitre_ids
from mirage.intel.synthetic import make_session_document


def _with_offered_keys(doc: dict, n: int) -> dict:
    out = copy.deepcopy(doc)
    first_ts = out["auth_attempts"][0]["timestamp_ms"]
    keys = [
        {
            "timestamp_ms": first_ts - 10 + i,
            "method": "publickey",
            "username": f"user{i}",
            "credential": f"ssh-ed25519 SHA256:key{i}",
            "success": False,
        }
        for i in range(n)
    ]
    out["auth_attempts"] = keys + out["auth_attempts"]
    return out


def test_offered_keys_do_not_change_features_or_mitre() -> None:
    doc = make_session_document("manual_recon", random.Random(5), 0)
    base = parse_session_document(doc)
    keyed = parse_session_document(_with_offered_keys(doc, 4))

    assert len(keyed.auth_attempts) == len(base.auth_attempts) + 4
    assert extract_features(keyed).as_dict() == extract_features(base).as_dict()
    assert map_mitre_ids(keyed) == map_mitre_ids(base)
