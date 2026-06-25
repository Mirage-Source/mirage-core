"""Environment-driven configuration for the enrichment bridge.

The database variables intentionally reuse the **same names the Go core uses**
(``DB_HOST``/``DB_PORT``/``DB_USER``/``DB_PASSWORD``/``DB_NAME``; see
``core/internal/store/store.go``) so both services read one ``.env`` file and hit
the same database with no duplicated configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["BridgeConfig", "load_config"]


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value is not None and value != "" else default


def _env_opt(name: str) -> str | None:
    value = os.getenv(name)
    return value if value else None


@dataclass
class BridgeConfig:
    """All bridge settings, resolved from the environment.

    Attributes:
        db_host/db_port/db_user/db_password/db_name: PostgreSQL connection,
            sharing the Go core's variable names.
        poll_interval_s: Seconds to sleep when no pending sessions are found.
        batch_size: Max sessions fetched and enriched per poll.
        require_finished: Only enrich sessions whose ``outcome`` is not
            ``"active"`` (finished sessions). The Go core only persists finished
            sessions, so this is a belt-and-suspenders guard.
        model_checkpoint: Path to a trained ``SessionEmbedder`` checkpoint
            (``best.pt``). If unset or missing, the worker runs in *degraded*
            mode -- timing + tool-signature enrichment only, no neural embedding.
        tokenizer_dir: Path to the saved tokenizer directory (``vocab.json`` +
            ``config.json``). Required iff a checkpoint is used.
        kmeans_artifact: Optional path to a saved KMeans/centroids ``.npz`` for
            assigning ``cluster_id`` (Phase-3 hook). Unset -> ``cluster_id`` null.
        model_version: Free-text tag stored alongside each embedding for
            provenance / reproducibility.
        device: Torch device (``"cpu"`` / ``"cuda"``); auto-detected if unset.
        max_length: Command-count cap when encoding a session.
        standardize_timing: Z-score the timing channel using tokenizer stats.
        ensure_schema: Run the idempotent ML-table DDL on startup (safety net if
            migrations were not applied).
    """

    db_host: str = "localhost"
    db_port: str = "5432"
    db_user: str = "mirage"
    db_password: str = "mirage"
    db_name: str = "mirage"

    poll_interval_s: float = 10.0
    batch_size: int = 32
    require_finished: bool = True

    model_checkpoint: str | None = None
    tokenizer_dir: str | None = None
    kmeans_artifact: str | None = None
    model_version: str = "mirage-emb-dev"
    classifier_checkpoint: str | None = None
    device: str | None = None
    max_length: int = 256
    standardize_timing: bool = True

    # Phase-4 threat-intel summary: off by default (no network/cost). Set
    # MIRAGE_INTEL_USE_LLM=1 (and ANTHROPIC_API_KEY) to generate Claude summaries;
    # MIRAGE_INTEL_MODEL overrides the model (default claude-opus-4-8).
    use_llm: bool = False
    intel_model: str | None = None

    ensure_schema: bool = True
    stix_enabled: bool = False

    def dsn(self) -> str:
        """libpq DSN string (sslmode disabled, matching the core's local setup)."""
        return (
            f"host={self.db_host} port={self.db_port} user={self.db_user} "
            f"password={self.db_password} dbname={self.db_name} sslmode=disable"
        )


def load_config() -> BridgeConfig:
    """Build a :class:`BridgeConfig` from environment variables."""
    return BridgeConfig(
        db_host=_env("DB_HOST", "localhost"),
        db_port=_env("DB_PORT", "5432"),
        db_user=_env("DB_USER", "mirage"),
        db_password=_env("DB_PASSWORD", "mirage"),
        db_name=_env("DB_NAME", "mirage"),
        poll_interval_s=float(_env("BRIDGE_POLL_INTERVAL_S", "10")),
        batch_size=int(_env("BRIDGE_BATCH_SIZE", "32")),
        require_finished=_env("BRIDGE_REQUIRE_FINISHED", "1") not in ("0", "false", "False"),
        model_checkpoint=_env_opt("MIRAGE_MODEL_CHECKPOINT"),
        tokenizer_dir=_env_opt("MIRAGE_TOKENIZER_DIR"),
        kmeans_artifact=_env_opt("MIRAGE_KMEANS_ARTIFACT"),
        model_version=_env("MIRAGE_MODEL_VERSION", "mirage-emb-dev"),
        classifier_checkpoint=_env_opt("MIRAGE_CLASSIFIER_CHECKPOINT"),
        device=_env_opt("MIRAGE_DEVICE"),
        max_length=int(_env("MIRAGE_MAX_LENGTH", "256")),
        standardize_timing=_env("MIRAGE_STANDARDIZE_TIMING", "1") not in ("0", "false", "False"),
        use_llm=_env("MIRAGE_INTEL_USE_LLM", "0") not in ("0", "false", "False"),
        intel_model=_env_opt("MIRAGE_INTEL_MODEL"),
        ensure_schema=_env("BRIDGE_ENSURE_SCHEMA", "1") not in ("0", "false", "False"),
        stix_enabled=_env("MIRAGE_STIX_ENABLED", "0") not in ("0", "false", "False"),
    )
