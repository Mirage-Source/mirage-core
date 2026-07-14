
from __future__ import annotations

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .actions import DeceptionAction
from .live import LiveDeceptionEngine, load_engine_from_env

__all__ = ["make_handler", "main"]

logger = logging.getLogger("mirage.deception.serve")

_MAX_BODY_BYTES = 16_384  # a command line is at most a few hundred bytes


def make_handler(engine: LiveDeceptionEngine, algo: str, checkpoint: str) -> type[BaseHTTPRequestHandler]:
    """Build a request-handler class closing over the loaded engine.

    (``http.server`` instantiates a fresh handler per request from the class
    passed to the server, so the engine -- and its per-session state -- has to
    be threaded in via closure rather than ``__init__`` args.)
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

        def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
            if self.path == "/health":
                self._json(200, {"status": "ok", "algo": algo, "checkpoint": checkpoint})
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
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

    return Handler


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=os.environ.get("MIRAGE_DECEPTION_LOG_LEVEL", "INFO"), stream=sys.stderr)

    engine = load_engine_from_env()
    algo = os.environ.get("MIRAGE_DECEPTION_ALGO", "ppo").lower()
    checkpoint = os.environ["MIRAGE_DECEPTION_CHECKPOINT"]
    port = int(os.environ.get("MIRAGE_DECEPTION_PORT", "8787"))
    host = os.environ.get("MIRAGE_DECEPTION_HOST", "0.0.0.0")

    handler_cls = make_handler(engine, algo, checkpoint)
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
