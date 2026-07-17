
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any

from mirage.analysis.timing import compute_timing_features
from mirage.intel.ingest import parse_session_document
from mirage.intel.pipeline import IntelPipeline

from .config import BridgeConfig

__all__ = ["EnrichmentResult", "Enricher"]

#: Minimum commands before a session is eligible for hash-based clustering --
#: below this, too many unrelated sessions would share a near-empty
#: normalized payload (e.g. a lone "ls") and collapse into a meaningless
#: cluster.
_MIN_COMMANDS_FOR_HASH_CLUSTER = 2

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _hash_cluster(session: Any) -> str | None:
    """Stopgap payload-fingerprint clustering, used while the real embedder
    (:meth:`Enricher._assign_cluster`) is untrained and idle.

    Hashes the session's normalized raw command sequence (IPv4 addresses
    replaced with a placeholder, so the same script pointed at a different
    C2/proxy IP per bot instance still matches) so sessions that received the
    same or near-identical attack payload land in the same cluster -- e.g.
    the ``mdrfckr`` SSH-key backdoor-implant payload seen reused verbatim
    across many bot IPs. This only catches exact/near-exact literal reuse,
    not behaviorally-similar-but-differently-worded attacks; that needs a
    trained embedding model, not a hash.
    """
    if len(session.commands) < _MIN_COMMANDS_FOR_HASH_CLUSTER:
        return None
    normalized = "\n".join(
        _IPV4_RE.sub("<ip>", cmd.raw.strip())
        for cmd in session.commands
        if cmd.raw.strip()
    )
    if not normalized:
        return None
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"payload:{digest}"


@dataclass
class EnrichmentResult:
    """The ML intelligence computed for one session.

    Fields map onto the core's ``sessions`` intelligence columns plus the
    ``session_embeddings`` table.
    """

    session_id: str
    # -> sessions.* intelligence columns
    attacker_class: str
    classifier_confidence: float | None
    cluster_id: str | None
    mitre_techniques: list[str]
    session_summary: str
    # -> session_embeddings.*
    tool_signature: str = "other"
    timing_label: str = "unknown"
    timing_cv: float | None = None
    timing_median_ms: float | None = None
    embedding: list[float] | None = None
    embedding_dim: int | None = None
    model_version: str | None = None
    trajectory: dict[str, Any] | None = None
    extras: dict[str, Any] = field(default_factory=dict)
    stix_bundle: dict | None = None


class Enricher:
    """Stateful enrichment engine; load once, call :meth:`enrich` per session.

    Loading the (optional) embedder, tokenizer and clustering artifact happens in
    the constructor so the per-session path is cheap. If model loading fails for
    any reason, the enricher logs and continues in degraded (no-embedding) mode
    rather than crashing the worker.

    Args:
        config: The bridge configuration (paths, device, model version, LLM flag).
    """

    def __init__(self, config: BridgeConfig) -> None:
        self.config = config
        self.model = None
        self.tokenizer = None
        self.analyzer = None
        self.device = None
        self._centroids = None
        self._centroid_ids: list[str] = []
        self.classifier = None  # NEW: SessionClassifier, loaded below

        self._maybe_load_model()
        self._maybe_load_classifier()  # NEW: must run after _maybe_load_model (shares device)
        self._maybe_load_centroids()

        # Build pipeline AFTER loading so the real classifier is passed in when
        # available. Falls back to weak labels (classifier=None) if not loaded.
        self._pipeline = IntelPipeline(
            classifier=self.classifier,
            use_llm=config.use_llm,
            model=config.intel_model,
            include_stix=config.stix_enabled,
        )

    @property
    def has_model(self) -> bool:
        """Whether neural embedding/trajectory enrichment is active."""
        return self.model is not None and self.tokenizer is not None

    # -- Loading ------------------------------------------------------------

    def _maybe_load_model(self) -> None:
        import os

        ckpt = self.config.model_checkpoint
        tok_dir = self.config.tokenizer_dir
        if not ckpt or not tok_dir or not os.path.exists(ckpt) or not os.path.isdir(tok_dir):
            print(
                "[enrich] no model checkpoint/tokenizer configured or found; "
                "running without embeddings (classification + MITRE + summary only)."
            )
            return
        try:
            import torch

            from mirage.models.embedding import SessionEmbedder, SessionEmbedderConfig
            from mirage.models.trajectory import TemporalTrajectoryAnalyzer, TrajectoryConfig
            from mirage.tokenizer.tokenizer import CommandTokenizer

            self.device = torch.device(
                self.config.device or ("cuda" if torch.cuda.is_available() else "cpu")
            )
            checkpoint = torch.load(ckpt, map_location=self.device, weights_only=True)
            model_cfg = SessionEmbedderConfig(**checkpoint["config"])
            model = SessionEmbedder(model_cfg).to(self.device)
            model.load_state_dict(checkpoint["state_dict"])
            model.eval()
            self.model = model
            self.tokenizer = CommandTokenizer.load(tok_dir)
            self.analyzer = TemporalTrajectoryAnalyzer(TrajectoryConfig(mode="prefix"))
            print(
                f"[enrich] loaded embedder ({model.num_parameters():,} params, "
                f"dim={model_cfg.embedding_dim}) on {self.device}; "
                f"vocab={self.tokenizer.vocab_size}."
            )
        except Exception as exc:  # noqa: BLE001 - degrade rather than crash
            print(f"[enrich] failed to load model ({exc}); continuing without embeddings.")
            self.model = None
            self.tokenizer = None

    def _maybe_load_classifier(self) -> None:
        """Load the trained SessionClassifier checkpoint if configured.

        Requires _maybe_load_model() to have run first so self.device is set.
        If loading fails for any reason, logs and continues with weak labels.
        """
        import os

        ckpt = self.config.classifier_checkpoint
        if not ckpt or not os.path.exists(ckpt):
            print(
                "[enrich] no classifier checkpoint configured or found; "
                "using weak-label (heuristic) attacker classification."
            )
            return
        try:
            import torch

            from mirage.intel.classifier import SessionClassifier, ClassifierConfig

            # Resolve device: reuse embedder device if already set, else detect.
            if self.device is None:
                self.device = torch.device(
                    self.config.device or ("cuda" if torch.cuda.is_available() else "cpu")
                )

            checkpoint = torch.load(ckpt, map_location=self.device, weights_only=True)
            clf_cfg = ClassifierConfig(**checkpoint["config"])
            clf = SessionClassifier(clf_cfg).to(self.device)
            clf.load_state_dict(checkpoint["state_dict"])
            clf.eval()
            self.classifier = clf
            print(
                f"[enrich] loaded classifier ({clf.num_parameters():,} params, "
                f"input_dim={clf_cfg.input_dim}, n_classes={clf_cfg.n_classes}) "
                f"on {self.device}."
            )
        except Exception as exc:  # noqa: BLE001 - degrade rather than crash
            print(f"[enrich] failed to load classifier ({exc}); falling back to weak labels.")
            self.classifier = None

    def _maybe_load_centroids(self) -> None:
        import os

        path = self.config.kmeans_artifact
        if not path or not os.path.exists(path):
            return
        try:
            import numpy as np

            data = np.load(path, allow_pickle=True)
            self._centroids = data["centroids"]
            ids = data.get("cluster_ids")
            self._centroid_ids = (
                [str(x) for x in ids]
                if ids is not None
                else [str(i) for i in range(len(self._centroids))]
            )
            print(f"[enrich] loaded {len(self._centroids)} cluster centroids.")
        except Exception as exc:  # noqa: BLE001
            print(f"[enrich] failed to load centroids ({exc}); cluster_id disabled.")
            self._centroids = None

    # -- Core enrichment ----------------------------------------------------

    def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        """Compute the full ML intelligence for one core ``session_document``.

        Args:
            document: The parsed ``session_document`` JSON (a marshaled Go
                session), as returned by ``db.fetch_pending``.
        """
        prod = parse_session_document(document)
        session = prod.session
        feats = compute_timing_features(session)

        # -- Phase-2 embedding + trajectory (optional) ----------------------
        embedding: list[float] | None = None
        embedding_dim: int | None = None
        trajectory: dict[str, Any] | None = None
        cluster_id: str | None = None
        model_version: str | None = None
        embedding_np = None

        if self.has_model and session.commands:
            import numpy as np

            embedding, hidden, _length = self._embed(session)
            embedding_dim = len(embedding)
            embedding_np = np.asarray(embedding, dtype=np.float32)
            model_version = self.config.model_version
            trajectory = self._trajectory(hidden)
            cluster_id = self._assign_cluster(embedding)

        if cluster_id is None:
            cluster_id = _hash_cluster(session)

        # -- Phase-4 intelligence (classification + MITRE + summary) --------
        intel = self._pipeline.enrich(
            document, embedding=embedding_np, cluster_id=cluster_id
        )

        return EnrichmentResult(
            session_id=session.session_id,
            attacker_class=intel.attacker_class,
            classifier_confidence=intel.classifier_confidence,
            cluster_id=intel.cluster_id,
            mitre_techniques=intel.mitre_techniques,
            session_summary=intel.session_summary,
            tool_signature=intel.tool_signature,
            timing_label=intel.timing_label,
            timing_cv=_nan_safe(feats.cv),
            timing_median_ms=_nan_safe(feats.median_ms),
            embedding=embedding,
            embedding_dim=embedding_dim,
            model_version=model_version,
            trajectory=trajectory,
            stix_bundle=intel.stix_bundle,
            extras={
                "severity": intel.severity,
                "recommended_actions": intel.recommended_actions,
                "classifier_source": intel.classifier_source,
                "summary_source": intel.summary_source,
            },
        )

    # -- Sub-steps ----------------------------------------------------------

    def _embed(self, session: Any) -> tuple[list[float], Any, int]:
        """Encode + embed a session; return (embedding, hidden_states, length)."""
        import torch

        enc = self.tokenizer.encode(  # type: ignore[union-attr]
            session,
            max_length=self.config.max_length,
            standardize_timing=self.config.standardize_timing,
        )
        input_ids = torch.tensor([enc.input_ids], dtype=torch.long, device=self.device)
        timing = torch.tensor([enc.timing], dtype=torch.float32, device=self.device)
        mask = torch.tensor([enc.attention_mask], dtype=torch.long, device=self.device)
        with torch.no_grad():
            out = self.model(input_ids, timing, mask)  # type: ignore[misc]
        embedding = out.pooled[0].cpu().tolist()
        hidden = out.hidden_states[0, : enc.length].cpu()
        return embedding, hidden, enc.length

    def _trajectory(self, hidden: Any) -> dict[str, Any]:
        """Run trajectory geometry on a session's hidden states."""
        feat = self.analyzer.analyze(hidden)  # type: ignore[union-attr]
        return {
            "path_length": feat.path_length,
            "mean_speed": feat.mean_speed,
            "total_curvature": feat.total_curvature,
            "straightness": feat.straightness,
            "convergence_step": feat.convergence_step,
            "intent_shift_count": int(feat.intent_shift_indices.numel()),
            "intent_shift_indices": feat.intent_shift_indices.tolist(),
            "shape_signature": feat.shape_signature.tolist(),
        }

    def _assign_cluster(self, embedding: list[float]) -> str | None:
        """Assign the nearest cluster centroid id (Phase-3 hook), if loaded."""
        if self._centroids is None:
            return None
        import numpy as np

        vec = np.asarray(embedding, dtype=np.float32)
        dists = np.linalg.norm(self._centroids - vec, axis=1)
        return self._centroid_ids[int(dists.argmin())]


def _nan_safe(value: float) -> float | None:
    """Return ``None`` for NaN/inf so the value is null-safe for the DB."""
    return float(value) if isinstance(value, (int, float)) and math.isfinite(value) else None
