"""
real_train.py

Phase-3 re-ID training on real MIRAGE sessions, using verified ground truth
(source address as identity, confirmed campaign-tier membership as an
auxiliary toolkit signal -- see mirage.reid.campaign and DECISIONS.md,
2026-08-26) instead of the synthetic identity corpus mirage.reid.train uses.

This is the "run once, review before it's trusted" step: it does not write
anything back to a dataset or retrain in a loop. That comes only after a
human has looked at this run's held-out re-ID metrics and toolkit-vs-identity
retrieval report and approved it.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import DataLoader, Subset

from ..models.embedding import SessionEmbedderConfig
from ..tokenizer.tokenizer import CommandTokenizer, TokenizerConfig
from ..training.schedule import cosine_warmup_schedule
from .augment import ReIDAugmentConfig
from .data import IdentityCorpus, reconnection_split
from .dataset import PKCollator, ReIDDataset
from .evaluate import reid_evaluate
from .loss import REID_TEMPERATURE, CampaignAwareReIDLoss
from .model import ContrastiveReIDModel, ReIDModelConfig
from .pk_sampler import PKBatchSampler
from .real_data import load_real_identity_corpus

__all__ = ["TrainRealReIDConfig", "RealReIDExperiment", "fit_real_reid", "train_real_reid", "main"]


@dataclass
class TrainRealReIDConfig:
    """Hyperparameters for real-data Phase-3 training."""

    # Data
    corpus_path: str = "data/reid/real_corpus.jsonl"
    min_sessions_per_identity: int = 1
    n_probe_per_identity: int = 1
    data_seed: int = 0

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

    # P-K batching (see mirage.reid.pk_sampler)
    p: int = 32
    k: int = 4
    batches_per_epoch: int = 200

    # Optimization
    epochs: int = 20
    lr: float = 3e-4
    weight_decay: float = 1e-2
    warmup_frac: float = 0.1
    min_lr_ratio: float = 0.01
    identity_temperature: float = REID_TEMPERATURE
    toolkit_temperature: float = REID_TEMPERATURE
    coarse_weight: float = 0.3
    grad_clip: float = 1.0

    # Augmentation
    augment: ReIDAugmentConfig = field(default_factory=ReIDAugmentConfig)

    # Infrastructure
    seed: int = 1337
    device: str | None = None
    ks: tuple[int, ...] = (1, 5, 10)
    output_dir: str | None = None
    run_name: str = "mirage-reid-real"
    verbose: bool = True


def _build_model(cfg: TrainRealReIDConfig, vocab_size: int, pad_id: int) -> ContrastiveReIDModel:
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
class RealReIDExperiment:
    """A fully trained real-data re-ID run, plus everything needed to report on it."""

    model: ContrastiveReIDModel
    dataset: ReIDDataset
    tokenizer: CommandTokenizer
    corpus: IdentityCorpus
    gallery_indices: list[int]
    probe_indices: list[int]
    metrics: dict[str, float]
    history: list[dict[str, float]]
    device: torch.device


def fit_real_reid(
    cfg: TrainRealReIDConfig, corpus: IdentityCorpus | None = None
) -> RealReIDExperiment:
    """Train the real-data re-ID model and return the full experiment.

    Args:
        cfg: Training configuration.
        corpus: Optional pre-loaded real :class:`IdentityCorpus` (e.g. for
            tests); loaded from ``cfg.corpus_path`` if omitted.
    """
    torch.manual_seed(cfg.seed)
    device = torch.device(cfg.device or ("cuda" if torch.cuda.is_available() else "cpu"))

    if corpus is None:
        corpus = load_real_identity_corpus(cfg.corpus_path)
    if cfg.min_sessions_per_identity > 1:
        # Re-filter in case the caller passed an unfiltered corpus.
        from .real_data import build_real_identity_corpus

        counts: dict[str, int] = {}
        for identity in corpus.identity_labels:
            counts[identity] = counts.get(identity, 0) + 1
        keep_ids = {i for i, lab in enumerate(corpus.identity_labels) if counts[lab] >= cfg.min_sessions_per_identity}
        corpus = IdentityCorpus(
            sessions=[s for i, s in enumerate(corpus.sessions) if i in keep_ids],
            identity_labels=[lab for i, lab in enumerate(corpus.identity_labels) if i in keep_ids],
            toolkit_labels=[t for i, t in enumerate(corpus.toolkit_labels) if i in keep_ids],
        )

    gallery_idx, probe_idx = reconnection_split(
        corpus.identity_labels, cfg.n_probe_per_identity, seed=cfg.data_seed
    )

    gallery_sessions = [corpus.sessions[i] for i in gallery_idx]
    tokenizer = CommandTokenizer(
        TokenizerConfig(mode=cfg.tokenizer_mode, top_k=cfg.top_k)
    ).fit(gallery_sessions)

    dataset = ReIDDataset.from_corpus(
        corpus, tokenizer, max_length=cfg.max_length, standardize_timing=cfg.standardize_timing
    )
    timing_std = tokenizer.config.timing_std if cfg.standardize_timing else 1.0
    collate = PKCollator(tokenizer, cfg.augment, timing_std=timing_std, seed=cfg.seed)

    gallery_identity_labels = [corpus.identity_labels[i] for i in gallery_idx]
    pk_sampler = PKBatchSampler(
        gallery_identity_labels,
        p=cfg.p,
        k=cfg.k,
        batches_per_epoch=cfg.batches_per_epoch,
        seed=cfg.seed,
    )
    train_loader = DataLoader(
        Subset(dataset, gallery_idx), batch_sampler=pk_sampler, collate_fn=collate
    )

    model = _build_model(cfg, tokenizer.vocab_size, tokenizer.pad_id).to(device)
    criterion = CampaignAwareReIDLoss(
        identity_temperature=cfg.identity_temperature,
        toolkit_temperature=cfg.toolkit_temperature,
        coarse_weight=cfg.coarse_weight,
    )
    optimizer = torch.optim.AdamW(
        (p for p in model.parameters() if p.requires_grad),
        lr=cfg.lr,
        weight_decay=cfg.weight_decay,
    )
    total_steps = cfg.batches_per_epoch * cfg.epochs
    scheduler = cosine_warmup_schedule(
        optimizer, int(total_steps * cfg.warmup_frac), total_steps, cfg.min_lr_ratio
    )

    if cfg.verbose:
        print(
            f"[real-reid] device={device} identities={corpus.n_identities} "
            f"gallery={len(gallery_idx)} probe={len(probe_idx)} "
            f"vocab={tokenizer.vocab_size} params={model.num_parameters():,} "
            f"p={cfg.p} k={cfg.k} batch={pk_sampler.batch_size} "
            f"coarse_weight={cfg.coarse_weight}"
        )

    history: list[dict[str, float]] = []
    for epoch in range(1, cfg.epochs + 1):
        model.train()
        epoch_loss, n = 0.0, 0
        for view, identity_labels, toolkit_labels in train_loader:
            view = view.to(device)
            z = model.project(view.input_ids, view.timing, view.attention_mask)
            loss = criterion(z, identity_labels, toolkit_labels)
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip)
            optimizer.step()
            scheduler.step()
            epoch_loss += float(loss.detach().item())
            n += 1
        history.append({"epoch": epoch, "loss": epoch_loss / max(1, n)})
        if cfg.verbose and (epoch == 1 or epoch % 5 == 0 or epoch == cfg.epochs):
            print(f"[real-reid] epoch {epoch:3d}/{cfg.epochs} loss={epoch_loss / max(1, n):.4f}")

    metrics = reid_evaluate(model, dataset, gallery_idx, probe_idx, ks=cfg.ks, device=device)
    if cfg.verbose:
        pretty = " ".join(
            f"{k}={v:.3f}" for k, v in metrics.items() if k.startswith(("recall", "mAP"))
        )
        print(f"[real-reid] held-out re-ID (same-address recovery): {pretty}")

    return RealReIDExperiment(
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


def train_real_reid(
    cfg: TrainRealReIDConfig, corpus: IdentityCorpus | None = None
) -> dict[str, Any]:
    """Train and return a serializable summary (and persist a checkpoint if
    ``cfg.output_dir`` is set)."""
    exp = fit_real_reid(cfg, corpus=corpus)
    summary: dict[str, Any] = {
        "metrics": exp.metrics,
        "final_loss": exp.history[-1]["loss"] if exp.history else float("nan"),
        "n_identities": exp.corpus.n_identities,
        "n_sessions": len(exp.corpus),
        "n_gallery": len(exp.gallery_indices),
        "n_probe": len(exp.probe_indices),
        "vocab_size": exp.tokenizer.vocab_size,
        "params": exp.model.num_parameters(),
        "coarse_weight": cfg.coarse_weight,
    }
    if cfg.output_dir:
        out = Path(cfg.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        exp.tokenizer.save(out / "tokenizer")
        torch.save(
            {
                "state_dict": exp.model.state_dict(),
                "augment_config": asdict(cfg.augment),
                "model_config": {
                    "backbone": asdict(exp.model.config.backbone),
                    "projection_hidden_dim": exp.model.config.projection_hidden_dim,
                    "projection_dim": exp.model.config.projection_dim,
                    "projection_use_bn": exp.model.config.projection_use_bn,
                },
            },
            out / f"{cfg.run_name}.pt",
        )
        (out / f"{cfg.run_name}_summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
    return summary


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpus-path", default="data/reid/real_corpus.jsonl")
    p.add_argument("--min-sessions-per-identity", type=int, default=1)
    p.add_argument("--p", type=int, default=32)
    p.add_argument("--k", type=int, default=4)
    p.add_argument("--batches-per-epoch", type=int, default=200)
    p.add_argument("--epochs", type=int, default=20)
    p.add_argument("--coarse-weight", type=float, default=0.3)
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--device", default=None)
    p.add_argument("--output-dir", default=None)
    p.add_argument("--run-name", default="mirage-reid-real")
    return p


def main(argv: list[str] | None = None) -> dict[str, Any]:
    args = _build_arg_parser().parse_args(argv)
    cfg = TrainRealReIDConfig(
        corpus_path=args.corpus_path,
        min_sessions_per_identity=args.min_sessions_per_identity,
        p=args.p,
        k=args.k,
        batches_per_epoch=args.batches_per_epoch,
        epochs=args.epochs,
        coarse_weight=args.coarse_weight,
        lr=args.lr,
        seed=args.seed,
        device=args.device,
        output_dir=args.output_dir,
        run_name=args.run_name,
    )
    result = train_real_reid(cfg)
    print(json.dumps(result, indent=2, default=str))
    return result


if __name__ == "__main__":  # pragma: no cover
    main()
