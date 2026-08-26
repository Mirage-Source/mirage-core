"""Tests for the LLM shell-completion fallback (completion.py).

Every test here drives the engine through fake providers rather than a real
model: the point under test is the surrounding machinery -- caching, budgets,
the circuit breaker, provider switching -- all of which must behave
identically no matter which vendor is behind it.
"""

from __future__ import annotations

import pytest

from mirage.deception.completion import (
    CompletionEngine,
    ProviderSpec,
    build_providers,
)


class FakeClock:
    """Manually advanced monotonic clock, so no test has to sleep."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class CountingProvider:
    """Records every call and returns a distinct canned answer per command."""

    def __init__(self, output: str = "canned output") -> None:
        self.calls: list[str] = []
        self.output = output

    def complete(self, command: str, session_id: str) -> str:
        self.calls.append(command)
        return f"{self.output}:{command}:{len(self.calls)}"


class FailingProvider:
    def __init__(self, exc: Exception | None = None) -> None:
        self.calls = 0
        self.exc = exc or RuntimeError("provider exploded")

    def complete(self, command: str, session_id: str) -> str:
        self.calls += 1
        raise self.exc


def make_engine(provider=None, **kwargs):
    provider = provider or CountingProvider()
    clock = kwargs.pop("clock", None) or FakeClock()
    defaults = dict(
        providers={"fake": provider},
        active="fake",
        max_per_session=10,
        global_rate_limit=100,
        rate_window_s=60.0,
        failure_threshold=3,
        cooldown_s=30.0,
        session_ttl_s=900.0,
        clock=clock,
    )
    defaults.update(kwargs)
    return CompletionEngine(**defaults), provider, clock


# --- Caching / consistency ---------------------------------------------------


def test_same_command_in_same_session_returns_identical_output() -> None:
    engine, provider, _ = make_engine()

    first = engine.complete("sess-1", "uptime")
    second = engine.complete("sess-1", "uptime")

    assert first["available"] and second["available"]
    assert first["output"] == second["output"]
    assert provider.calls == ["uptime"], "repeat must be served from cache, not re-asked"


def test_different_sessions_do_not_share_cached_output() -> None:
    engine, provider, _ = make_engine()

    engine.complete("sess-1", "uptime")
    engine.complete("sess-2", "uptime")

    assert provider.calls == ["uptime", "uptime"]


def test_distinct_commands_each_hit_the_provider() -> None:
    engine, provider, _ = make_engine()

    engine.complete("sess-1", "uptime")
    engine.complete("sess-1", "nproc")

    assert provider.calls == ["uptime", "nproc"]


# --- Per-session budget ------------------------------------------------------


def test_per_session_budget_stops_further_completions() -> None:
    engine, provider, _ = make_engine(max_per_session=2)

    assert engine.complete("s", "a")["available"]
    assert engine.complete("s", "b")["available"]
    third = engine.complete("s", "c")

    assert not third["available"]
    assert provider.calls == ["a", "b"]


def test_cached_repeat_does_not_consume_budget() -> None:
    engine, provider, _ = make_engine(max_per_session=2)

    engine.complete("s", "a")
    engine.complete("s", "a")  # cached, should be free
    assert engine.complete("s", "b")["available"], "cache hit must not spend budget"


def test_budget_is_per_session_not_global() -> None:
    engine, _, _ = make_engine(max_per_session=1)

    assert engine.complete("s1", "a")["available"]
    assert engine.complete("s2", "a")["available"]


# --- Global rate limit -------------------------------------------------------


def test_global_rate_limit_applies_across_sessions() -> None:
    engine, provider, _ = make_engine(global_rate_limit=2, max_per_session=99)

    assert engine.complete("s1", "a")["available"]
    assert engine.complete("s2", "b")["available"]
    assert not engine.complete("s3", "c")["available"]
    assert provider.calls == ["a", "b"]


def test_global_rate_limit_window_slides() -> None:
    clock = FakeClock()
    engine, _, _ = make_engine(global_rate_limit=1, rate_window_s=60.0, clock=clock)

    assert engine.complete("s1", "a")["available"]
    assert not engine.complete("s2", "b")["available"]

    clock.advance(61.0)
    assert engine.complete("s3", "c")["available"], "old calls must age out of the window"


# --- Circuit breaker ---------------------------------------------------------


def test_provider_failure_fails_safe_rather_than_raising() -> None:
    engine, provider, _ = make_engine(provider=FailingProvider())

    result = engine.complete("s", "uptime")

    assert result["available"] is False
    assert provider.calls == 1


def test_circuit_opens_after_consecutive_failures() -> None:
    provider = FailingProvider()
    engine, _, _ = make_engine(provider=provider, failure_threshold=3)

    for i in range(3):
        engine.complete("s", f"cmd{i}")
    assert provider.calls == 3

    engine.complete("s", "cmd-after-open")
    assert provider.calls == 3, "open circuit must not call the provider at all"


def test_circuit_closes_after_cooldown() -> None:
    provider = FailingProvider()
    clock = FakeClock()
    engine, _, _ = make_engine(
        provider=provider, failure_threshold=2, cooldown_s=30.0, clock=clock
    )

    engine.complete("s", "a")
    engine.complete("s", "b")
    engine.complete("s", "c")
    assert provider.calls == 2

    clock.advance(31.0)
    engine.complete("s", "d")
    assert provider.calls == 3, "cooldown elapsed -- provider should be retried"


def test_success_resets_the_failure_counter() -> None:
    class FlakyProvider:
        def __init__(self) -> None:
            self.calls = 0

        def complete(self, command: str, session_id: str) -> str:
            self.calls += 1
            if command == "bad":
                raise RuntimeError("nope")
            return "fine"

    provider = FlakyProvider()
    engine, _, _ = make_engine(provider=provider, failure_threshold=2)

    engine.complete("s", "bad")
    engine.complete("s", "good")  # success resets the streak
    engine.complete("s", "bad")
    # One failure, one success, one failure -- never two in a row, so the
    # circuit must still be closed and the next call must reach the provider.
    assert engine.complete("s", "good2")["available"]


# --- Provider output validation ---------------------------------------------


def test_blank_provider_output_is_not_offered_as_a_completion() -> None:
    class BlankProvider:
        def complete(self, command: str, session_id: str) -> str:
            return "   \n  "

    engine, _, _ = make_engine(provider=BlankProvider())
    assert engine.complete("s", "uptime")["available"] is False


def test_output_is_truncated_to_the_configured_cap() -> None:
    class HugeProvider:
        def complete(self, command: str, session_id: str) -> str:
            return "x" * 100_000

    engine, _, _ = make_engine(provider=HugeProvider(), max_output_chars=500)
    result = engine.complete("s", "uptime")
    assert result["available"]
    assert len(result["output"]) <= 500


# --- Provider switching ------------------------------------------------------


def test_set_active_switches_which_provider_serves() -> None:
    a, b = CountingProvider("A"), CountingProvider("B")
    engine = CompletionEngine(
        providers={"a": a, "b": b}, active="a", clock=FakeClock()
    )

    engine.complete("s", "uptime")
    assert a.calls and not b.calls

    assert engine.set_active("b") is True
    engine.complete("s2", "uptime")
    assert b.calls


def test_set_active_rejects_unknown_provider() -> None:
    engine, _, _ = make_engine()
    assert engine.set_active("nope") is False
    assert engine.active == "fake", "a rejected switch must not change the active provider"


def test_engine_with_no_providers_is_unavailable_not_broken() -> None:
    engine = CompletionEngine(providers={}, active=None, clock=FakeClock())
    assert engine.complete("s", "uptime")["available"] is False
    assert engine.stats()["active"] is None


# --- Session TTL eviction ----------------------------------------------------


def test_stale_sessions_are_evicted() -> None:
    clock = FakeClock()
    engine, provider, _ = make_engine(session_ttl_s=100.0, clock=clock)

    engine.complete("s", "uptime")
    clock.advance(101.0)
    engine.complete("other", "trigger-eviction-sweep")
    engine.complete("s", "uptime")

    assert provider.calls.count("uptime") == 2, "evicted session must not keep its cache"


# --- Provider construction from config --------------------------------------


def test_build_providers_parses_spec_list() -> None:
    specs = [
        ProviderSpec(name="fast", kind="anthropic", model="claude-haiku-4-5-20251001"),
        ProviderSpec(
            name="local",
            kind="openai_compatible",
            model="qwen2.5:7b",
            base_url="http://localhost:11434/v1",
        ),
    ]
    providers = build_providers(specs)
    assert set(providers) == {"fast", "local"}


def test_build_providers_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unknown provider kind"):
        build_providers([ProviderSpec(name="x", kind="telepathy", model="m")])


def test_provider_spec_from_json_never_accepts_a_raw_key() -> None:
    """Config carries the NAME of an env var, never a secret itself."""
    specs = ProviderSpec.list_from_json(
        '[{"name":"p","provider":"anthropic","model":"m","api_key_env":"MY_KEY"}]'
    )
    assert specs[0].api_key_env == "MY_KEY"
    assert not hasattr(specs[0], "api_key")


def test_provider_spec_list_from_blank_json_is_empty() -> None:
    assert ProviderSpec.list_from_json("") == []
    assert ProviderSpec.list_from_json("   ") == []


# --- HTTP wire contract ------------------------------------------------------
#
# These are the first tests in this repo to exercise serve.py over a real
# socket. They exist because the field names below are a contract with Go's
# internal/deception.Client.Complete: a rename on either side is silent at
# compile time and shows up only as "the fallback mysteriously never fires".


import json as _json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from mirage.deception.serve import make_handler


class _StubLiveEngine:
    def decide(self, session_id, command, bait_hit):
        return {"action": 0, "action_name": "MINIMAL", "category": None}


def _serve(completion):
    handler = make_handler(_StubLiveEngine(), "ppo", "/dev/null", completion)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _post(url, payload):
    req = urllib.request.Request(
        url, data=_json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, _json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _json.loads(exc.read())


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, _json.loads(resp.read())


def test_complete_endpoint_returns_the_fields_go_expects() -> None:
    engine, _, _ = make_engine()
    httpd, base = _serve(engine)
    try:
        status, body = _post(f"{base}/complete", {"session_id": "s", "command": "uptime"})
    finally:
        httpd.shutdown()

    assert status == 200
    assert set(body) >= {"available", "output", "exit_code"}
    assert body["available"] is True
    assert isinstance(body["output"], str) and body["output"]
    assert isinstance(body["exit_code"], int)


def test_complete_endpoint_reports_unavailable_when_not_configured() -> None:
    httpd, base = _serve(None)
    try:
        status, body = _post(f"{base}/complete", {"session_id": "s", "command": "uptime"})
    finally:
        httpd.shutdown()

    assert status == 200, "an unconfigured fallback is a 200 + available=false, not an error"
    assert body["available"] is False


def test_complete_endpoint_stays_200_on_a_malformed_body() -> None:
    engine, _, _ = make_engine()
    httpd, base = _serve(engine)
    try:
        req = urllib.request.Request(
            f"{base}/complete", data=b"{not json", headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            status, body = resp.status, _json.loads(resp.read())
    finally:
        httpd.shutdown()

    assert status == 200
    assert body["available"] is False


def test_decide_endpoint_still_works_alongside_the_new_routes() -> None:
    engine, _, _ = make_engine()
    httpd, base = _serve(engine)
    try:
        status, body = _post(f"{base}/decide", {"session_id": "s", "command": "ls", "bait_hit": False})
    finally:
        httpd.shutdown()

    assert status == 200
    assert body["action_name"] == "MINIMAL"


def test_provider_listing_never_exposes_a_secret() -> None:
    engine, _, _ = make_engine()
    engine.specs = {
        "p": ProviderSpec(name="p", kind="anthropic", model="m", api_key_env="SECRET_ENV")
    }
    httpd, base = _serve(engine)
    try:
        status, body = _get(f"{base}/llm-providers")
    finally:
        httpd.shutdown()

    assert status == 200
    assert body["configured"] is True
    serialized = _json.dumps(body)
    assert "SECRET_ENV" not in serialized, "the key env var name must not leak to the dashboard"
    assert body["providers"][0]["model"] == "m"


def test_set_active_endpoint_switches_provider() -> None:
    a, b = CountingProvider("A"), CountingProvider("B")
    engine = CompletionEngine(providers={"a": a, "b": b}, active="a", clock=FakeClock())
    httpd, base = _serve(engine)
    try:
        status, body = _post(f"{base}/llm-providers/active", {"name": "b"})
        assert status == 200 and body["active"] == "b"

        bad_status, _ = _post(f"{base}/llm-providers/active", {"name": "nope"})
        assert bad_status == 400
    finally:
        httpd.shutdown()

    assert engine.active == "b"
