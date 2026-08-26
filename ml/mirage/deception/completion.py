"""LLM-backed shell-completion fallback for commands the Go shell can't handle.

The Go interpreter (``internal/shell``) answers a fixed set of builtins with
curated, self-consistent output. Anything else has always fallen through to
``bash: <cmd>: command not found``, which is both a fingerprint and a dead
end for engagement -- the preprint measured 2.79% of sessions issuing any
command at all. This module answers a narrow slice of those unknown commands
with generated, plausible output instead.

What reaches this module is already tightly filtered on the Go side (see
``internal/deception/completion.go``): single simple commands only, never a
builtin, and never anything egress-flavoured. Nothing here should be the only
thing standing between an attacker and a fabricated "download succeeded".

Every failure path in this module returns ``available=False`` rather than
raising, mirroring the fail-safe contract the rest of the deception service
already follows: the honeypot must behave exactly as it always has whenever
this feature can't answer.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

__all__ = [
    "CompletionEngine",
    "ProviderSpec",
    "AnthropicProvider",
    "OpenAICompatibleProvider",
    "build_providers",
    "engine_from_env",
    "DEFAULT_ANTHROPIC_MODEL",
]

logger = logging.getLogger("mirage.deception.completion")

#: Default Anthropic model for shell completion. Deliberately the small/fast
#: model rather than the most capable one: this call sits on an attacker's
#: interactive shell prompt, where a multi-second pause is itself a honeypot
#: tell. Operators who want a stronger model can configure one per provider.
DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"

#: Hard ceiling on generated output. A real `uptime` prints one line; nothing
#: in scope for this fallback legitimately prints tens of kilobytes, and an
#: unbounded response is both a cost and a plausibility problem.
DEFAULT_MAX_OUTPUT_CHARS = 4000

_SYSTEM_PROMPT = (
    "You generate realistic terminal output for a defensive SSH honeypot's "
    "simulated Linux environment. The host is a decoy operated by your own "
    "organization; no real system is involved and no real command is ever "
    "executed. Given a command, emit exactly what a real Ubuntu 22.04 server "
    "would print to the terminal for it -- nothing else. No explanations, no "
    "markdown, no code fences, no commentary. Keep it terse and plausible for "
    "a small cloud VPS. Never claim that a network operation, download, "
    "transfer, or remote login occurred. Never include instructions for "
    "carrying out an attack."
)

_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "output": {
            "type": "string",
            "description": (
                "Exactly what the command prints to the terminal. Empty string "
                "if the real command would print nothing."
            ),
        },
        "exit_code": {
            "type": "integer",
            "description": "The exit status the real command would return (usually 0).",
        },
    },
    "required": ["output", "exit_code"],
    "additionalProperties": False,
}

_TOOL_NAME = "emit_terminal_output"


def _build_user_prompt(command: str, hostname: str) -> str:
    return (
        f"Host: {hostname} (Ubuntu 22.04 LTS, small cloud VPS, single non-root "
        f"user 'ubuntu')\n"
        f"Command: {command}\n\n"
        f"Emit the terminal output for this command."
    )


# --- Providers ---------------------------------------------------------------


class Provider(Protocol):
    """One configured way to generate terminal output."""

    def complete(self, command: str, session_id: str) -> str:  # pragma: no cover
        ...


@dataclass
class ProviderSpec:
    """Declarative description of one provider, from configuration.

    Attributes:
        name: Operator-chosen label, shown in the dashboard.
        kind: ``anthropic`` or ``openai_compatible``.
        model: Model identifier passed to that vendor's API.
        api_key_env: Name of the environment variable holding the API key --
            never the key itself, so configuration can be logged, dumped to
            the dashboard, or committed without leaking a secret.
        base_url: Only for ``openai_compatible``; points at OpenAI proper when
            unset, or at any OpenAI-compatible server (Ollama, vLLM, LM Studio)
            when set.
    """

    name: str
    kind: str
    model: str
    api_key_env: str | None = None
    base_url: str | None = None

    @classmethod
    def list_from_json(cls, raw: str) -> list[ProviderSpec]:
        """Parse MIRAGE_LLM_SHELL_PROVIDERS_JSON. Blank input means no providers."""
        if not raw or not raw.strip():
            return []
        entries = json.loads(raw)
        specs: list[ProviderSpec] = []
        for entry in entries:
            specs.append(
                cls(
                    name=entry["name"],
                    kind=entry.get("provider", "anthropic"),
                    model=entry["model"],
                    api_key_env=entry.get("api_key_env"),
                    base_url=entry.get("base_url"),
                )
            )
        return specs

    def public_dict(self) -> dict[str, Any]:
        """Dashboard-safe view: no secret can appear here by construction."""
        return {
            "name": self.name,
            "provider": self.kind,
            "model": self.model,
            "base_url": self.base_url,
        }


class AnthropicProvider:
    """Anthropic-backed completion, using forced tool-use for structured output.

    Mirrors the pattern already proven in ``mirage/intel/summarize.py``: lazy
    import so the package has no hard dependency, a JSON schema submitted as a
    forced tool so the reply is parsed rather than scraped, and the client
    injectable for tests.
    """

    def __init__(
        self,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        api_key_env: str | None = None,
        hostname: str = "ip-172-31-14-52",
        client: Any | None = None,
    ) -> None:
        self.model = model
        self.api_key_env = api_key_env
        self.hostname = hostname
        self._client = client

    def _ensure_client(self) -> Any:
        if self._client is None:
            import anthropic  # lazily, so importing this module needs no SDK

            kwargs = {}
            if self.api_key_env:
                kwargs["api_key"] = os.environ[self.api_key_env]
            self._client = anthropic.Anthropic(**kwargs)
        return self._client

    def complete(self, command: str, session_id: str) -> str:
        client = self._ensure_client()
        response = client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _build_user_prompt(command, self.hostname)}],
            tools=[
                {
                    "name": _TOOL_NAME,
                    "description": "Emit the terminal output for the given command.",
                    "input_schema": _OUTPUT_SCHEMA,
                }
            ],
            tool_choice={"type": "tool", "name": _TOOL_NAME},
        )
        tool_use = next(b for b in response.content if b.type == "tool_use")
        return str(tool_use.input.get("output", ""))


class OpenAICompatibleProvider:
    """OpenAI-protocol completion, covering OpenAI proper and self-hosted servers.

    One implementation serves both because Ollama, vLLM and LM Studio all
    expose the OpenAI chat-completions API; the only difference is ``base_url``.
    That keeps "multi-vendor" to two client implementations rather than one per
    runtime.
    """

    def __init__(
        self,
        model: str,
        api_key_env: str | None = None,
        base_url: str | None = None,
        hostname: str = "ip-172-31-14-52",
        client: Any | None = None,
    ) -> None:
        self.model = model
        self.api_key_env = api_key_env
        self.base_url = base_url
        self.hostname = hostname
        self._client = client

    def _ensure_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI  # lazily, same reasoning as above

            kwargs: dict[str, Any] = {}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            if self.api_key_env:
                kwargs["api_key"] = os.environ[self.api_key_env]
            elif self.base_url:
                # Self-hosted servers ignore the key but the SDK requires one.
                kwargs["api_key"] = "not-needed"
            self._client = OpenAI(**kwargs)
        return self._client

    def complete(self, command: str, session_id: str) -> str:
        client = self._ensure_client()
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=1024,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(command, self.hostname)},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": _TOOL_NAME,
                    "schema": _OUTPUT_SCHEMA,
                    "strict": True,
                },
            },
        )
        payload = json.loads(response.choices[0].message.content)
        return str(payload.get("output", ""))


def build_providers(specs: list[ProviderSpec], hostname: str = "ip-172-31-14-52") -> dict[str, Provider]:
    """Instantiate every configured provider. Raises on an unknown kind."""
    providers: dict[str, Provider] = {}
    for spec in specs:
        if spec.kind == "anthropic":
            providers[spec.name] = AnthropicProvider(
                model=spec.model, api_key_env=spec.api_key_env, hostname=hostname
            )
        elif spec.kind == "openai_compatible":
            providers[spec.name] = OpenAICompatibleProvider(
                model=spec.model,
                api_key_env=spec.api_key_env,
                base_url=spec.base_url,
                hostname=hostname,
            )
        else:
            raise ValueError(f"unknown provider kind {spec.kind!r} for provider {spec.name!r}")
    return providers


# --- Engine ------------------------------------------------------------------


@dataclass
class _SessionState:
    """Per-session cache and budget counter."""

    cache: dict[str, tuple[str, int]]
    spent: int
    last_seen: float


class CompletionEngine:
    """Thread-safe completion dispatcher with caching, budgets and a breaker.

    Structurally mirrors ``LiveDeceptionEngine`` in ``live.py`` -- one lock, a
    per-session dict, TTL eviction -- because this service serves both from the
    same ``ThreadingHTTPServer`` and there is no reason for two shapes.

    The three guards each answer a different failure mode:

    * **Per-session cache** gives consistency. An attacker running ``uptime``
      twice must see the same uptime both times; a fresh generation each time
      is an obvious tell.
    * **Budgets** (per-session and a global sliding window) bound cost. This
      endpoint is reachable by anyone who can open a TCP connection to the
      honeypot, so an unbounded spend per attacker is a real exposure, not a
      hypothetical one.
    * **Circuit breaker** bounds damage from a sick provider: after enough
      consecutive failures it stops calling out entirely for a cooldown,
      rather than adding provider latency to every command while it's down.
    """

    def __init__(
        self,
        providers: dict[str, Provider],
        active: str | None,
        max_per_session: int = 25,
        global_rate_limit: int = 600,
        rate_window_s: float = 60.0,
        failure_threshold: int = 5,
        cooldown_s: float = 60.0,
        session_ttl_s: float = 900.0,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._providers = dict(providers)
        self._active = active if active in self._providers else None
        self._max_per_session = max_per_session
        self._global_rate_limit = global_rate_limit
        self._rate_window_s = rate_window_s
        self._failure_threshold = failure_threshold
        self._cooldown_s = cooldown_s
        self._session_ttl_s = session_ttl_s
        self._max_output_chars = max_output_chars
        self._clock = clock

        self._lock = threading.Lock()
        self._sessions: dict[str, _SessionState] = {}
        self._recent_calls: list[float] = []
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0
        self._served = 0
        self._refused = 0

    @property
    def active(self) -> str | None:
        with self._lock:
            return self._active

    def set_active(self, name: str) -> bool:
        """Switch the serving provider. Returns False for an unknown name."""
        with self._lock:
            if name not in self._providers:
                return False
            self._active = name
            # A switch is an operator saying "try something else"; holding a
            # breaker open from the previous provider's failures would make
            # the new one look broken too.
            self._consecutive_failures = 0
            self._circuit_open_until = 0.0
            return True

    def stats(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            return {
                "active": self._active,
                "providers": sorted(self._providers),
                "served": self._served,
                "refused": self._refused,
                "circuit_open": now < self._circuit_open_until,
                "consecutive_failures": self._consecutive_failures,
                "recent_calls": len(self._recent_calls),
                "tracked_sessions": len(self._sessions),
            }

    def _unavailable(self) -> dict[str, Any]:
        self._refused += 1
        return {"available": False, "output": "", "exit_code": 0}

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self._session_ttl_s
        for sid in [s for s, st in self._sessions.items() if st.last_seen < cutoff]:
            del self._sessions[sid]

    def complete(self, session_id: str, command: str) -> dict[str, Any]:
        """Answer one command, or report that no completion is available."""
        with self._lock:
            now = self._clock()
            self._evict_stale(now)

            state = self._sessions.get(session_id)
            if state is None:
                state = _SessionState(cache={}, spent=0, last_seen=now)
                self._sessions[session_id] = state
            state.last_seen = now

            # A cache hit is free: it costs no provider call, so it is checked
            # ahead of every budget and the breaker.
            cached = state.cache.get(command)
            if cached is not None:
                output, exit_code = cached
                self._served += 1
                return {"available": True, "output": output, "exit_code": exit_code}

            if self._active is None:
                return self._unavailable()
            if now < self._circuit_open_until:
                return self._unavailable()
            if state.spent >= self._max_per_session:
                return self._unavailable()

            self._recent_calls = [t for t in self._recent_calls if t > now - self._rate_window_s]
            if len(self._recent_calls) >= self._global_rate_limit:
                return self._unavailable()

            provider = self._providers[self._active]
            active_name = self._active
            self._recent_calls.append(now)
            state.spent += 1

        # The provider call happens OUTSIDE the lock: it is a network round
        # trip measured in seconds, and holding the lock across it would
        # serialize every concurrent session behind one slow request.
        try:
            raw = provider.complete(command, session_id)
        except Exception as exc:  # noqa: BLE001 -- fail safe on anything
            logger.warning("completion provider %s failed for %r: %s", active_name, command, exc)
            with self._lock:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self._failure_threshold:
                    self._circuit_open_until = self._clock() + self._cooldown_s
                    logger.warning(
                        "completion circuit opened after %d consecutive failures; "
                        "pausing provider calls for %.0fs",
                        self._consecutive_failures,
                        self._cooldown_s,
                    )
                return self._unavailable()

        output = (raw or "").strip("\n")
        if not output.strip():
            # A blank answer is not usable output; treat it as a miss rather
            # than printing an empty line where a real tool prints something.
            with self._lock:
                self._consecutive_failures = 0
                return self._unavailable()

        if len(output) > self._max_output_chars:
            output = output[: self._max_output_chars]

        with self._lock:
            self._consecutive_failures = 0
            state = self._sessions.get(session_id)
            if state is not None:
                state.cache[command] = (output, 0)
            self._served += 1

        return {"available": True, "output": output, "exit_code": 0}


def engine_from_env() -> CompletionEngine:
    """Build a CompletionEngine from MIRAGE_LLM_SHELL_* environment variables."""

    def _int(key: str, default: int) -> int:
        try:
            return int(os.getenv(key, "") or default)
        except ValueError:
            return default

    def _float(key: str, default: float) -> float:
        try:
            return float(os.getenv(key, "") or default)
        except ValueError:
            return default

    specs = ProviderSpec.list_from_json(os.getenv("MIRAGE_LLM_SHELL_PROVIDERS_JSON", ""))
    hostname = os.getenv("MIRAGE_LLM_SHELL_HOSTNAME", "ip-172-31-14-52")
    providers = build_providers(specs, hostname=hostname)

    active = os.getenv("MIRAGE_LLM_SHELL_ACTIVE_PROVIDER") or (specs[0].name if specs else None)

    engine = CompletionEngine(
        providers=providers,
        active=active,
        max_per_session=_int("MIRAGE_LLM_SHELL_MAX_PER_SESSION", 25),
        global_rate_limit=_int("MIRAGE_LLM_SHELL_GLOBAL_RATE_LIMIT", 600),
        rate_window_s=_float("MIRAGE_LLM_SHELL_RATE_WINDOW_S", 60.0),
        failure_threshold=_int("MIRAGE_LLM_SHELL_FAILURE_THRESHOLD", 5),
        cooldown_s=_float("MIRAGE_LLM_SHELL_COOLDOWN_S", 60.0),
        session_ttl_s=_float("MIRAGE_LLM_SHELL_SESSION_TTL_S", 900.0),
        max_output_chars=_int("MIRAGE_LLM_SHELL_MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS),
    )
    # Kept as a public attribute so /llm-providers can render model/base_url
    # without the engine having to carry vendor detail through its own API.
    engine.specs = {s.name: s for s in specs}  # type: ignore[attr-defined]
    return engine
