"""The MIRAGE enrichment worker: a long-running poll-enrich-write loop.

    while running:
        batch = fetch sessions with NULL attacker_class
        for each: adapt (core->ML) -> enrich (ML stack) -> write back
        sleep if the batch was empty

This is the only process that connects the Go honeypot to the Python ML layer,
and it does so entirely through the shared Postgres database -- no code changes to
the core, no synchronous coupling. Run it as a sidecar container next to the core
(see ../docker-compose.yml) or standalone:

    python -m bridge.worker            # uses environment / .env for config
    python -m bridge.worker --once     # single pass then exit (useful for tests/cron)
"""

from __future__ import annotations

import argparse
import signal
import time
from types import FrameType

from .config import BridgeConfig, load_config
from .db import (
    connect_with_retry,
    ensure_schema,
    fetch_pending,
    mark_failed,
    write_enrichment,
)
from .enrich import Enricher

__all__ = ["run", "main"]


class _Shutdown:
    """Cooperative shutdown flag flipped by SIGINT/SIGTERM."""

    def __init__(self) -> None:
        self.stop = False

    def request(self, signum: int, frame: FrameType | None) -> None:  # noqa: ARG002
        print(f"[worker] received signal {signum}; finishing current batch then exiting.")
        self.stop = True


def _process_batch(conn, enricher: Enricher, batch) -> int:
    """Adapt, enrich and persist one batch. Returns the count successfully written."""
    written = 0
    for session_id, doc in batch:
        try:
            result = enricher.enrich(doc)
            write_enrichment(conn, result)
            written += 1
            print(
                f"[worker] {session_id[:8]} -> class={result.attacker_class} "
                f"conf={result.classifier_confidence} tool={result.tool_signature} "
                f"timing={result.timing_label} "
                f"sev={result.extras.get('severity', '-')} "
                f"embed={'yes' if result.embedding is not None else 'no'}"
            )
        except Exception as exc:  # noqa: BLE001 - isolate poison sessions
            conn.rollback()
            try:
                mark_failed(conn, session_id, str(exc))
            except Exception as inner:  # noqa: BLE001
                print(f"[worker] {session_id[:8]} could not be marked failed: {inner}")
            print(f"[worker] {session_id[:8]} enrichment error: {exc}")
    return written


def run(config: BridgeConfig | None = None, once: bool = False) -> None:
    """Run the enrichment loop.

    Args:
        config: Bridge configuration; loaded from the environment if omitted.
        once: If ``True``, process a single (possibly empty) pass and return --
            otherwise loop until a shutdown signal is received.
    """
    config = config or load_config()
    shutdown = _Shutdown()
    signal.signal(signal.SIGINT, shutdown.request)
    signal.signal(signal.SIGTERM, shutdown.request)

    print(
        f"[worker] starting; db={config.db_host}:{config.db_port}/{config.db_name} "
        f"batch={config.batch_size} poll={config.poll_interval_s}s"
    )
    enricher = Enricher(config)
    embed_mode = "with embeddings + trajectory" if enricher.has_model else "no embeddings"
    summary_mode = "LLM" if config.use_llm else "template"
    print(
        f"[worker] enrichment: Phase-4 intelligence (classification + MITRE + "
        f"{summary_mode} summary) {embed_mode}"
    )

    conn = connect_with_retry(config)
    try:
        if config.ensure_schema:
            ensure_schema(conn)
            print("[worker] ML schema ensured.")

        total = 0
        while not shutdown.stop:
            batch = fetch_pending(conn, config.batch_size, config.require_finished)
            if not batch:
                if once:
                    print("[worker] no pending sessions; --once drain complete.")
                    break
                _sleep_interruptible(config.poll_interval_s, shutdown)
                continue
            total += _process_batch(conn, enricher, batch)
            if total % 50 < len(batch):  # crude "crossed a multiple of 50" check
                print(f"[worker] {total} sessions enriched so far.")
            # In --once mode, keep draining batches until none remain.
    finally:
        conn.close()
        print(f"[worker] stopped after enriching {total} session(s).")


def _sleep_interruptible(seconds: float, shutdown: _Shutdown) -> None:
    """Sleep in short ticks so a shutdown signal is honored promptly."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not shutdown.stop:
        time.sleep(min(0.5, deadline - time.monotonic()))


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once", action="store_true",
        help="Process all currently-pending sessions once, then exit.",
    )
    args = parser.parse_args(argv)
    run(once=args.once)


if __name__ == "__main__":  # pragma: no cover
    main()
