"""Run the MIRAGE ML stack on a single session -> an ``EnrichmentResult``.

This is where Phase-1 and Phase-2 are actually applied to live honeypot data:

1. **Timing heuristic** (Phase 1) -- automated vs. human cadence from the ICI
   distribution.
2. **Tool-signature inference** (weak label) -- coarse attack family from command
   content.
3. **Session embedding** (Phase 2) -- the 128-d behavioral vector, *if* a trained
   ``SessionEmbedder`` checkpoint is configured.
4. **Trajectory analysis** (Phase 2) -- velocity / curvature / convergence of the
   session's path through embedding space (the motor-cortex analogy).
5. **MITRE ATT&CK mapping** + a templated **session summary**.

The :class:`Enricher` degrades gracefully: with no model checkpoint it still
produces a useful attacker classification, MITRE mapping and summary from timing
+ tool signature (so the honeypot is informative on day one), and upgrades to full
neural embeddings + trajectory geometry the moment a checkpoint is dropped in.

LLM-based summarization and a learned real-time classifier are later phases; the
``attacker_class``/``confidence``/``summary`` produced here are transparent
heuristics, tagged as such via ``model_version``.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from mirage.analysis.timing import classify_session, compute_timing_features
from mirage.data.schema import Session
from mirage.viz.tool_signature import infer_tool_signature

from .config import BridgeConfig

__all__ = ["EnrichmentResult", "Enricher"]


#: Coarse tool-family -> MITRE ATT&CK technique IDs. Deliberately small and
#: auditable; expand as the tool-signature taxonomy grows.
MITRE_BY_TOOL: dict[str, list[str]] = {
    "dropper": ["T1105", "T1059"],          # Ingress Tool Transfer; Cmd/Scripting
    "miner": ["T1496"],                     # Resource Hijacking
    "ddos_botnet": ["T1498", "T1059"],      # Network DoS; Cmd/Scripting
    "recon": ["T1082", "T1033"],            # System Info / Owner-User Discovery
    "persistence": ["T1098", "T1053", "T1136"],  # Acct Manip; Scheduled; Create Acct
    "defense_evasion": ["T1070", "T1562"],  # Indicator Removal; Impair Defenses
    "other": [],
}

#: Human-readable phrase per attacker class, for the templated summary.
_CLASS_PHRASE: dict[str, str] = {
    "dropper": "Payload-dropper",
    "miner": "Cryptominer-install",
    "ddos_botnet": "DDoS-botnet",
    "recon": "Reconnaissance",
    "persistence": "Persistence-establishing",
    "defense_evasion": "Defense-evasion",
    "automated": "Automated",
    "human": "Interactive (human)",
    "unknown": "Unclassified",
}


@dataclass
class EnrichmentResult:
    """The ML intelligence computed for one session.

    Fields map onto the core's ``sessions`` intelligence columns plus the new
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


class Enricher:
    """Stateful enrichment engine; load once, call :meth:`enrich` per session.

    Loading the (optional) embedder, tokenizer and clustering artifact happens in
    the constructor so the per-session path is cheap. If model loading fails for
    any reason, the enricher logs and continues in degraded (no-embedding) mode
    rather than crashing the worker.

    Args:
        config: The bridge configuration (paths, device, model version).
    """

    def __init__(self, config: BridgeConfig) -> None:
        self.config = config
        self.model = None
        self.tokenizer = None
        self.analyzer = None
        self.device = None
        self._centroids = None  # [k, D] numpy array for cluster assignment
        self._centroid_ids: list[str] = []
        self._maybe_load_model()
        self._maybe_load_centroids()

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
                "running in degraded mode (timing + tool-signature only)."
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
            checkpoint = torch.load(ckpt, map_location=self.device)
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
            print(f"[enrich] failed to load model ({exc}); degraded mode.")
            self.model = None
            self.tokenizer = None

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

    def enrich(self, session: Session) -> EnrichmentResult:
        """Compute the full ML intelligence for one session."""
        feats = compute_timing_features(session)
        timing_label = classify_session(session, features=feats)
        tool_sig = infer_tool_signature(session.raw_commands())

        attacker_class, confidence = self._classify(tool_sig, timing_label, session.n_commands)

        embedding: list[float] | None = None
        embedding_dim: int | None = None
        trajectory: dict[str, Any] | None = None
        cluster_id: str | None = None
        model_version: str | None = None

        if self.has_model and session.commands:
            embedding, hidden, length = self._embed(session)
            embedding_dim = len(embedding)
            model_version = self.config.model_version
            trajectory = self._trajectory(hidden, length)
            cluster_id = self._assign_cluster(embedding)

        mitre = list(MITRE_BY_TOOL.get(tool_sig, []))
        summary = self._summarize(
            session, attacker_class, tool_sig, timing_label, feats, trajectory
        )

        return EnrichmentResult(
            session_id=session.session_id,
            attacker_class=attacker_class,
            classifier_confidence=confidence,
            cluster_id=cluster_id,
            mitre_techniques=mitre,
            session_summary=summary,
            tool_signature=tool_sig,
            timing_label=timing_label,
            timing_cv=None if feats.cv != feats.cv else float(feats.cv),  # nan-safe
            timing_median_ms=None if feats.median_ms != feats.median_ms else float(feats.median_ms),
            embedding=embedding,
            embedding_dim=embedding_dim,
            model_version=model_version,
            trajectory=trajectory,
        )

    # -- Sub-steps ----------------------------------------------------------

    def _classify(
        self, tool_sig: str, timing_label: str, n_commands: int
    ) -> tuple[str, float]:
        """Combine the tool signature and timing label into a class + confidence.

        Heuristic pre-Phase-4: the tool signature (if any) is the class; timing
        corroboration raises confidence; with neither signal we fall back to the
        timing label. Confidences are deliberately modest -- these are weak labels,
        not a calibrated classifier.
        """
        if n_commands == 0:
            return "unknown", 0.5
        if tool_sig != "other":
            # Corroboration by an automated cadence bumps confidence.
            conf = 0.75 if timing_label == "automated" else 0.66
            return tool_sig, conf
        if timing_label in ("automated", "human"):
            return timing_label, 0.55
        return "unknown", 0.5

    def _embed(self, session: Session) -> tuple[list[float], Any, int]:
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

    def _trajectory(self, hidden: Any, length: int) -> dict[str, Any]:
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

    def _summarize(
        self,
        session: Session,
        attacker_class: str,
        tool_sig: str,
        timing_label: str,
        feats: Any,
        trajectory: dict[str, Any] | None,
    ) -> str:
        """Build a compact, templated session summary (LLM summary is later phase)."""
        phrase = _CLASS_PHRASE.get(attacker_class, attacker_class)
        dur_s = session.effective_duration_ms / 1000.0
        parts = [
            f"{phrase} session from {session.ip}: {session.n_commands} commands "
            f"over {dur_s:.1f}s"
        ]
        if feats.n_deltas > 0 and feats.median_ms == feats.median_ms:
            cv_txt = "n/a" if feats.cv != feats.cv else f"{feats.cv:.2f}"
            parts.append(
                f"median inter-command gap {feats.median_ms:.0f}ms (CV {cv_txt}, "
                f"{timing_label} cadence)"
            )
        if tool_sig != "other":
            parts.append(f"tool signature '{tool_sig}'")
        if session.bait_interactions:
            touched = sorted({b.bait_type for b in session.bait_interactions})
            parts.append("touched bait: " + ", ".join(touched))
        if trajectory is not None:
            parts.append(
                f"trajectory had {trajectory['intent_shift_count']} intent-shift "
                f"moment(s), converged after {trajectory['convergence_step']} "
                f"commands (straightness {trajectory['straightness']:.2f})"
            )
        return "; ".join(parts) + "."
