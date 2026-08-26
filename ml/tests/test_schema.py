from __future__ import annotations

from datetime import datetime, timezone

from mirage.data.schema import AuthAttempt, Command, Session


def test_session_round_trips_banner_and_auth_attempts() -> None:
    session = Session(
        session_id="s1",
        ip="1.2.3.4",
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ssh_client_banner="SSH-2.0-Go",
        auth_attempts=[
            AuthAttempt(username="root", credential="123456"),
            AuthAttempt(username="admin", credential="admin"),
        ],
    )
    session.commands.append(Command(timestamp=session.start_time, raw="uname -a", ms_offset=0))

    restored = Session.from_dict(session.to_dict())

    assert restored.ssh_client_banner == "SSH-2.0-Go"
    assert [(a.username, a.credential) for a in restored.auth_attempts] == [
        ("root", "123456"),
        ("admin", "admin"),
    ]
    assert restored.raw_commands() == ["uname -a"]


def test_session_defaults_are_backward_compatible_with_old_serialized_rows() -> None:
    # A row written before ssh_client_banner/auth_attempts existed.
    old_row = {
        "session_id": "s1",
        "ip": "1.2.3.4",
        "start_time": "2026-01-01T00:00:00.000000Z",
        "commands": [],
        "bait_interactions": [],
        "classifier_output": None,
    }
    session = Session.from_dict(old_row)
    assert session.ssh_client_banner == ""
    assert session.auth_attempts == []
