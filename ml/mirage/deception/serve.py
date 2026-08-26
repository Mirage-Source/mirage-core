
from __future__ import annotations

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .actions import DeceptionAction
from .completion import CompletionEngine, engine_from_env as completion_engine_from_env
from .live import LiveDeceptionEngine, load_engine_from_env

__all__ = ["make_handler", "main"]

logger = logging.getLogger("mirage.deception.serve")

_MAX_BODY_BYTES = 16_384  # a command line is at most a few hundred bytes


def make_handler(
    engine: LiveDeceptionEngine,
    algo: str,
    checkpoint: str,
    completion: CompletionEngine | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class closing over the loaded engines.

    (``http.server`` instantiates a fresh handler per request from the class
    passed to the server, so the engines -- and their per-session state -- have
    to be threaded in via closure rather than ``__init__`` args.)

    ``completion`` is optional: when it is None the LLM shell-completion
    fallback is simply never available, and /complete says so rather than
    erroring, so the policy service runs exactly as before with the feature
    unconfigured.
    """

    class Handler(BaseHTTPRequestHandler):
        server_version = "MirageDeception/1.0"

        def log_message(self, fmt: str, *args) -> None:  # quiet the default stderr access log
            logger.debug(fmt, *args)

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict | None:
            """Read and parse a bounded JSON body, or None if unusable."""
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > _MAX_BODY_BYTES:
                return None
            try:
                return json.loads(self.rfile.read(length))
            except Exception as exc:  # noqa: BLE001
                logger.warning("malformed request body on %s: %s", self.path, exc)
                return None

        def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
            if self.path == "/health":
                self._json(200, {"status": "ok", "algo": algo, "checkpoint": checkpoint})
            elif self.path == "/llm-providers":
                self._json(200, _provider_listing(completion))
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/complete":
                self._handle_complete()
                return
            if self.path == "/llm-providers/active":
                self._handle_set_active()
                return
            if self.path != "/decide":
                self._json(404, {"error": "not found"})
                return

            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > _MAX_BODY_BYTES:
                self._json(
                    400,
                    {"action": int(DeceptionAction.MINIMAL), "action_name": "MINIMAL", "error": "invalid content-length"},
                )
                return

            try:
                raw = self.rfile.read(length)
                payload = json.loads(raw)
                session_id = str(payload["session_id"])
                command = str(payload.get("command", ""))
                bait_hit = bool(payload.get("bait_hit", False))
            except Exception as exc:  # noqa: BLE001 -- any malformed input fails safe, never crashes
                logger.warning("malformed /decide request: %s", exc)
                self._json(
                    400,
                    {"action": int(DeceptionAction.MINIMAL), "action_name": "MINIMAL", "error": "malformed request"},
                )
                return

            try:
                decision = engine.decide(session_id, command, bait_hit)
            except Exception as exc:  # noqa: BLE001 -- inference must never take the shell down with it
                logger.exception("engine.decide failed; falling back to MINIMAL: %s", exc)
                decision = {"action": int(DeceptionAction.MINIMAL), "action_name": "MINIMAL", "category": None}

            self._json(200, decision)

        def _handle_complete(self) -> None:
            """Answer one unknown-command completion.

            Always HTTP 200 with an ``available`` flag, never a 5xx: the Go
            caller treats any non-200 the same as available=false anyway, and
            a status code would imply the *service* is broken when the usual
            reason is a deliberate refusal (budget spent, breaker open, no
            provider configured).
            """
            unavailable = {"available": False, "output": "", "exit_code": 0}

            if completion is None:
                self._json(200, unavailable)
                return

            payload = self._read_json_body()
            if payload is None:
                self._json(200, unavailable)
                return
            try:
                session_id = str(payload["session_id"])
                command = str(payload.get("command", ""))
            except Exception as exc:  # noqa: BLE001
                logger.warning("malformed /complete request: %s", exc)
                self._json(200, unavailable)
                return

            try:
                result = completion.complete(session_id, command)
            except Exception as exc:  # noqa: BLE001 -- must never take the shell down
                logger.exception("completion failed; reporting unavailable: %s", exc)
                result = unavailable

            self._json(200, result)

        def _handle_set_active(self) -> None:
            if completion is None:
                self._json(404, {"error": "completion not configured"})
                return
            payload = self._read_json_body()
            if payload is None or "name" not in payload:
                self._json(400, {"error": "expected {\"name\": ...}"})
                return
            if not completion.set_active(str(payload["name"])):
                self._json(400, {"error": "unknown provider"})
                return
            self._json(200, _provider_listing(completion))

    return Handler


def _provider_listing(completion: CompletionEngine | None) -> dict:
    """Dashboard-facing view of configured providers and live counters.

    Provider specs are rendered through ``ProviderSpec.public_dict``, which
    carries the api_key_env *name* rather than any secret -- so this response
    is safe to expose to the dashboard and to log.
    """
    if completion is None:
        return {"configured": False, "providers": [], "active": None, "stats": {}}

    specs = getattr(completion, "specs", {})
    return {
        "configured": True,
        "providers": [s.public_dict() for s in specs.values()],
        "active": completion.active,
        "stats": completion.stats(),
    }


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=os.environ.get("MIRAGE_DECEPTION_LOG_LEVEL", "INFO"), stream=sys.stderr)

    engine = load_engine_from_env()
    algo = os.environ.get("MIRAGE_DECEPTION_ALGO", "ppo").lower()
    checkpoint = os.environ["MIRAGE_DECEPTION_CHECKPOINT"]
    port = int(os.environ.get("MIRAGE_DECEPTION_PORT", "8787"))
    host = os.environ.get("MIRAGE_DECEPTION_HOST", "0.0.0.0")

    try:
        completion = completion_engine_from_env()
    except Exception as exc:  # noqa: BLE001 -- bad completion config must not stop the policy service
        logger.exception("LLM shell completion disabled -- bad configuration: %s", exc)
        completion = None
    if completion is not None:
        logger.info(
            "LLM shell completion: %d provider(s) configured, active=%s",
            len(completion.stats()["providers"]),
            completion.active,
        )

    handler_cls = make_handler(engine, algo, checkpoint, completion)
    httpd = ThreadingHTTPServer((host, port), handler_cls)
    logger.info("mirage-deception-serve listening on %s:%d (algo=%s checkpoint=%s)", host, port, algo, checkpoint)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":  # pragma: no cover
    main()
