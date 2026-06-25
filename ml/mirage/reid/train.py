"""End-to-end training for the contrastive re-identification model.

Trains :class:`~mirage.reid.model.ContrastiveReIDModel` with NT-Xent (``tau=0.07``)
on identity-preserving augmentations, then reports the re-ID protocol metrics
(recall@k, mAP) on a held-out reconnection split. Training is **self-supervised**:
positives are two augmentations of the *same* session, exactly as in Phase 2 --
the identity labels are used only at *evaluation*, to test whether the learned
metric re-identifies genuine reconnections it never saw paired. The backbone may
be warm-started from a Phase-2 checkpoint (``--backbone-checkpoint``).

Run::

    # Smoke test on a synthetic identity corpus (no data needed):
    python -m mirage.reid.train --synthetic --epochs 5 --n-identities 40

    # Warm-start the backbone from a Phase-2 embedding checkpoint:
    python -m mirage.reid.train --synthetic --backbone-checkpoint artifacts/embedder/best.pt
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import DataLoader, Subset

from ..models.embedding import SessionEmbedderConfig
from ..tokenizer.tokenizer import CommandTokenizer, TokenizerConfig
from ..training.schedule import cosine_warmup_schedule
from .augment import ReIDAugmentConfig
from .data import IdentityCorpus, make_identity_corpus, reconnection_split
from .dataset import ReIDCollator, ReIDDataset
from .evaluate import reid_evaluate
from .loss import REID_TEMPERATURE, reid_ntxent_loss
from .model import ContrastiveReIDModel, ReIDModelConfig

__all__ = [
    "TrainReIDConfig",
    "ReIDExperiment",
    "fit_reid",
    "train_reid",
    "augmentation_ablation",
    "main",
]


@dataclass
class TrainReIDConfig:
    """All Phase-3 training hyperparameters in one serializable place."""

    # Data (synthetic identity corpus)
    n_identities: int = 60
    sessions_per_identity: int = 5
    length_min: int = 6
    length_max: int = 18
    data_seed: int = 0
    n_probe_per_identity: int = 1

    # Tokenizer
    tokenizer_mode: str = "command"
    top_k: int = 500
    max_length: int = 64
    standardize_timing: bool = True

    # Backbone (Phase-2 SessionEmbedder)
    d_model: int = 128
    n_layers: int = 2
    n_heads: int = 4
    dropout: float = 0.1
    embedding_dim: int = 128
    use_timing: bool = True
    backbone_checkpoint: str | None = None
    freeze_backbone: bool = False

    # Projection head
    projection_hidden_dim: int = 128
    projection_dim: int = 64
    projection_use_bn: bool = True

    # Optimization
    epochs: int = 30
    batch_size: int = 128
    lr: float = 3e-4
    weight_decay: float = 1e-2
    warmup_frac: float = 0.1
    min_lr_ratio: float = 0.01
    temperature: float = REID_TEMPERATURE
    grad_clip: float = 1.0

    # Augmentation
    augment: ReIDAugmentConfig = field(default_factory=ReIDAugmentConfig)

    # Infrastructure
    seed: int = 1337
    device: str | None = None
    ks: tuple[int, ...] = (1, 5, 10)
    output_dir: str | None = None
    run_name: str = "mirage-reid"
    verbose: bool = True


def _build_model(cfg: TrainReIDConfig, vocab_size: int, pad_id: int) -> ContrastiveReIDModel:
    """Construct the re-ID model, optionally warm-starting the backbone."""
    if cfg.backbone_checkpoint:
        model = ContrastiveReIDModel.from_backbone_checkpoint(
            cfg.backbone_checkpoint,
            projection_hidden_dim=cfg.projection_hidden_dim,
            projection_dim=cfg.projection_dim,
            projection_use_bn=cfg.projection_use_bn,
        )
    else:
        backbone_cfg = SessionEmbedderConfig(
            vocab_size=vocab_size,
            d_model=cfg.d_model,
            n_layers=cfg.n_layers,
            n_heads=cfg.n_heads,
            dropout=cfg.dropout,
            embedding_dim=cfg.embedding_dim,
            pad_id=pad_id,
            max_len=cfg.max_length + 8,
            use_timing=cfg.use_timing,
        )
        model = ContrastiveReIDModel(
            ReIDModelConfig(
                backbone=backbone_cfg,
                projection_hidden_dim=cfg.projection_hidden_dim,
                projection_dim=cfg.projection_dim,
                projection_use_bn=cfg.projection_use_bn,
            )
        )
    if cfg.freeze_backbone:
        model.freeze_backbone()
    return model


@dataclass
class ReIDExperiment:
    """A fully trained re-ID run -- the model plus everything needed to evaluate,
    attack, or fingerprint it without re-training.

    Attributes:
        model: The trained :class:`ContrastiveReIDModel`.
        dataset: The encoded :class:`ReIDDataset` over the whole corpus.
        tokenizer: The fitted tokenizer.
        corpus: The identity corpus used.
        gallery_indices / probe_indices: The reconnection split into ``dataset``.
        metrics: Held-out re-ID metrics (recall@k, mAP).
        history: Per-epoch training loss.
        device: The compute device the model lives on.
    """

    model: ContrastiveReIDModel
    dataset: ReIDDataset
    tokenizer: CommandTokenizer
    corpus: IdentityCorpus
    gallery_indices: list[int]
    probe_indices: list[int]
    metrics: dict[str, float]
    history: list[dict[str, float]]
    device: torch.device


def fit_reid(
    cfg: TrainReIDConfig, corpus: IdentityCorpus | None = None
) -> ReIDExperiment:
    """Train the re-ID model and return the full :class:`ReIDExperiment`.

    This is the reusable core (no file I/O): the evaluation, adversarial, and
    fingerprint suites all consume the returned experiment.

    Args:
        cfg: Training configuration.
        corpus: Optional pre-built identity corpus (e.g. shared across an
            ablation); a fresh synthetic corpus is generated if omitted.
    """
    torch.manual_seed(cfg.seed)
    device = torch.device(cfg.device or ("cuda" if torch.cuda.is_available() else "cpu"))

    # -- Data + reconnection split -----------------------------------------
    if corpus is None:
        corpus = make_identity_corpus(
            n_identities=cfg.n_identities,
            sessions_per_identity=cfg.sessions_per_identity,
            length_range=(cfg.length_min, cfg.length_max),
            seed=cfg.data_seed,
        )
    gallery_idx, probe_idx = reconnection_split(
        corpus.identity_labels, cfg.n_probe_per_identity, seed=cfg.data_seed
    )

    # Tokenizer fit on the *gallery* only (probes are unseen at train time).
    gallery_sessions = [corpus.sessions[i] for i in gallery_idx]
    tokenizer = CommandTokenizer(
        TokenizerConfig(mode=cfg.tokenizer_mode, top_k=cfg.top_k)
    ).fit(gallery_sessions)

    dataset = ReIDDataset.from_corpus(
        corpus, tokenizer, max_length=cfg.max_length, standardize_timing=cfg.standardize_timing
    )
    timing_std = tokenizer.config.timing_std if cfg.standardize_timing else 1.0
    collate = ReIDCollator(tokenizer, cfg.augment, timing_std=timing_std, seed=cfg.seed)

    batch_size = min(cfg.batch_size, max(2, len(gallery_idx) // 2))
    train_loader = DataLoader(
        Subset(dataset, gallery_idx),
        batch_size=batch_size,
        shuffle=True,
        drop_last=len(gallery_idx) >= 2 * batch_size,
        collate_fn=collate,
    )

    # -- Model + optimizer --------------------------------------------------
    model = _build_model(cfg, tokenizer.vocab_size, tokenizer.pad_id).to(device)
    criterion = reid_ntxent_loss(cfg.temperature)
    optimizer = torch.optim.AdamW(
        (p for p in model.parameters() if p.requires_grad),
        lr=cfg.lr,
        weight_decay=cfg.weight_decay,
    )
    steps_per_epoch = max(1, len(train_loader))
    total_steps = steps_per_epoch * cfg.epochs
    scheduler = cosine_warmup_schedule(
        optimizer, int(total_steps * cfg.warmup_frac), total_steps, cfg.min_lr_ratio
    )

    if cfg.verbose:
        print(
            f"[reid] device={device} identities={corpus.n_identities} "
            f"gallery={len(gallery_idx)} probe={len(probe_idx)} "
            f"vocab={tokenizer.vocab_size} params={model.num_parameters():,} "
            f"tau={cfg.temperature} batch={batch_size}"
        )

    # -- Train loop ---------------------------------------------------------
    history: list[dict[str, float]] = []
    for epoch in range(1, cfg.epochs + 1):
        model.train()
        epoch_loss, n = 0.0, 0
        for view1, view2 in train_loader:
            view1, view2 = view1.to(device), view2.to(device)
            z1 = model.project(view1.input_ids, view1.timing, view1.attention_mask)
            z2 = model.project(view2.input_ids, view2.timing, view2.attention_mask)
            loss = criterion(z1, z2)
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip)
            optimizer.step()
            scheduler.step()
            epoch_loss += float(loss.detach().item())
            n += 1
        history.append({"epoch": epoch, "loss": epoch_loss / max(1, n)})
        if cfg.verbose and (epoch == 1 or epoch % 10 == 0 or epoch == cfg.epochs):
            print(f"[reid] epoch {epoch:3d}/{cfg.epochs} loss={epoch_loss / max(1, n):.4f}")

    # -- Evaluate re-ID -----------------------------------------------------
    metrics = reid_evaluate(model, dataset, gallery_idx, probe_idx, ks=cfg.ks, device=device)
    if cfg.verbose:
        pretty = " ".join(
            f"{k}={v:.3f}" for k, v in metrics.items() if k.startswith(("recall", "mAP"))
        )
        print(f"[reid] held-out re-ID: {pretty}")

    return ReIDExperiment(
        model=model,
        dataset=dataset,
        tokenizer=tokenizer,
        corpus=corpus,
        gallery_indices=list(gallery_idx),
        probe_indices=list(probe_idx),
        metrics=metrics,
        history=history,
        device=device,
    )


def train_reid(
    cfg: TrainReIDConfig, corpus: IdentityCorpus | None = None
) -> dict[str, Any]:
    """Train the re-ID model and return a serializable summary (and optionally
    persist a checkpoint when ``cfg.output_dir`` is set).

    Returns:
        Summary dict with held-out re-ID metrics and run metadata.
    """
    exp = fit_reid(cfg, corpus=corpus)
    summary: dict[str, Any] = {
        "metrics": exp.metrics,
        "final_loss": exp.history[-1]["loss"] if exp.history else math.nan,
        "n_identities": exp.corpus.n_identities,
        "n_gallery": len(exp.gallery_indices),
        "n_probe": len(exp.probe_indices),
        "vocab_size": exp.tokenizer.vocab_size,
        "params": exp.model.num_parameters(),
        "temperature": cfg.temperature,
    }

    if cfg.output_dir:
        out = Path(cfg.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        exp.tokenizer.save(out / "tokenizer")
        torch.save(
            {
                "state_dict": exp.model.state_dict(),
                "augment_config": asdict(cfg.augment),
                "model_config": _model_config_dict(exp.model),
            },
            out / f"{cfg.run_name}.pt",
        )
        (out / f"{cfg.run_name}_summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
    return summary


def _model_config_dict(model: ContrastiveReIDModel) -> dict[str, Any]:
    """Serialize the model architecture config for checkpointing."""
    return {
        "backbone": asdict(model.config.backbone),
        "projection_hidden_dim": model.config.projection_hidden_dim,
        "projection_dim": model.config.projection_dim,
        "projection_use_bn": model.config.projection_use_bn,
    }


# ---------------------------------------------------------------------------
# Augmentation ablation (Deliverable 4)
# ---------------------------------------------------------------------------


def _ablation_variants() -> dict[str, ReIDAugmentConfig]:
    """Leave-one-in augmentation configs: isolate each augmentation's effect.

    ``none`` (no augmentation -> trivial collapse baseline), each augmentation
    alone, and ``all`` (the full Phase-3 augmenter). Comparing the single-
    augmentation runs against ``all`` shows which augmentation contributes most to
    re-identification accuracy.
    """
    def cfg(drop: float, shuffle: float, jitter: float) -> ReIDAugmentConfig:
        return ReIDAugmentConfig(drop_prob=drop, shuffle_prob=shuffle, jitter_prob=jitter)

    return {
        "none": cfg(0.0, 0.0, 0.0),
        "drop_only": cfg(1.0, 0.0, 0.0),
        "shuffle_only": cfg(0.0, 1.0, 0.0),
        "jitter_only": cfg(0.0, 0.0, 1.0),
        "all": cfg(0.9, 0.9, 0.9),
    }


def augmentation_ablation(
    base_cfg: TrainReIDConfig | None = None,
    variants: dict[str, ReIDAugmentConfig] | None = None,
    corpus: IdentityCorpus | None = None,
) -> dict[str, dict[str, float]]:
    """Train+evaluate the model under each augmentation variant on one corpus.

    Args:
        base_cfg: Base training config (its ``augment`` field is overridden per
            variant); a short default run is used if omitted.
        variants: Mapping ``name -> ReIDAugmentConfig``; defaults to the leave-one-
            in set (none / drop_only / shuffle_only / jitter_only / all).
        corpus: Shared identity corpus so every variant sees identical data
            (generated once if omitted).

    Returns:
        ``{variant_name: reid_metrics}`` -- compare ``recall@1`` across variants to
        rank augmentation importance.
    """
    base_cfg = base_cfg or TrainReIDConfig(epochs=15, verbose=False)
    variants = variants or _ablation_variants()
    if corpus is None:
        corpus = make_identity_corpus(
            n_identities=base_cfg.n_identities,
            sessions_per_identity=base_cfg.sessions_per_identity,
            length_range=(base_cfg.length_min, base_cfg.length_max),
            seed=base_cfg.data_seed,
        )

    results: dict[str, dict[str, float]] = {}
    for name, aug in variants.items():
        cfg = TrainReIDConfig(**{**asdict(base_cfg), "augment": aug, "verbose": False})
        summary = train_reid(cfg, corpus=corpus)
        results[name] = summary["metrics"]
        if base_cfg.verbose:
            print(f"[ablation] {name:14s} recall@1={summary['metrics']['recall@1']:.3f}")
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--synthetic", action="store_true", help="Use a synthetic identity corpus.")
    p.add_argument("--n-identities", type=int, default=60)
    p.add_argument("--sessions-per-identity", type=int, default=5)
    p.add_argument("--data-seed", type=int, default=0)
    p.add_argument("--max-length", type=int, default=64)
    p.add_argument("--top-k", type=int, default=500)
    p.add_argument("--tokenizer-mode", choices=["command", "full"], default="command")

    p.add_argument("--backbone-checkpoint", default=None, help="Warm-start the backbone.")
    p.add_argument("--freeze-backbone", action="store_true")
    p.add_argument("--projection-dim", type=int, default=64)

    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--batch-size", type=int, default=128)
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--temperature", type=float, default=REID_TEMPERATURE)
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--device", default=None)
    p.add_argument("--output-dir", default=None)
    p.add_argument("--run-name", default="mirage-reid")
    p.add_argument("--ablation", action="store_true", help="Run the augmentation ablation instead.")
    return p


def main(argv: list[str] | None = None) -> dict[str, Any]:
    """CLI entry point."""
    args = _build_arg_parser().parse_args(argv)
    cfg = TrainReIDConfig(
        n_identities=args.n_identities,
        sessions_per_identity=args.sessions_per_identity,
        data_seed=args.data_seed,
        max_length=args.max_length,
        top_k=args.top_k,
        tokenizer_mode=args.tokenizer_mode,
        backbone_checkpoint=args.backbone_checkpoint,
        freeze_backbone=args.freeze_backbone,
        projection_dim=args.projection_dim,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        temperature=args.temperature,
        seed=args.seed,
        device=args.device,
        output_dir=args.output_dir,
        run_name=args.run_name,
    )
    if args.ablation:
        result = augmentation_ablation(cfg)
    else:
        result = train_reid(cfg)
    print(json.dumps(result, indent=2, default=str))
    return result


if __name__ == "__main__":  # pragma: no cover
    main()
