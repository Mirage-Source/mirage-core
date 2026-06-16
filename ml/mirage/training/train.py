"""End-to-end training loop for MIRAGE Phase-2 session embeddings.

Trains :class:`~mirage.models.embedding.SessionEmbedder` self-supervised with the
NT-Xent contrastive objective on public Cowrie data (or a synthetic corpus for
smoke tests). Features required by the Phase-2 spec:

* **Cosine LR schedule with linear warmup** (``training/schedule.py``).
* **Gradient checkpointing** for long sessions (per encoder layer), toggled by a
  flag so short-session runs pay no overhead.
* **Train/val loss logging to wandb or CSV** -- wandb if installed and enabled,
  otherwise a plain CSV so runs are always recorded with no extra dependency.

Run::

    # Smoke test on a synthetic corpus (no real logs needed):
    python -m mirage.training.train --synthetic --epochs 3 --batch-size 64

    # Real data:
    python -m mirage.training.train --input /path/to/cowrie/logs \\
        --epochs 50 --batch-size 256 --gradient-checkpointing \\
        --wandb --run-name mirage-emb-v1
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch.utils.data import DataLoader

from ..data.loader import DataLoader as SessionLoader
from ..data.schema import Session
from ..models.embedding import SessionEmbedder, SessionEmbedderConfig
from ..tokenizer.tokenizer import CommandTokenizer, TokenizerConfig
from .augment import AugmentConfig
from .dataset import ContrastiveCollator, SessionDataset
from .objective import NTXentLoss, alignment_loss, uniformity_loss
from .schedule import cosine_warmup_schedule

__all__ = ["TrainConfig", "MetricLogger", "train", "main"]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class TrainConfig:
    """All training hyperparameters in one serializable place (for the run log)."""

    # Data
    input: str | None = None
    synthetic: bool = False
    synthetic_sessions: int = 800
    pattern: str = "*.json*"
    min_commands: int = 2
    max_length: int = 256
    val_frac: float = 0.1
    tokenizer_mode: str = "command"
    top_k: int = 500
    standardize_timing: bool = True

    # Model
    d_model: int = 128
    n_layers: int = 2
    n_heads: int = 4
    dropout: float = 0.1
    embedding_dim: int = 128
    use_timing: bool = True

    # Optimization
    epochs: int = 30
    batch_size: int = 256
    lr: float = 3e-4
    weight_decay: float = 1e-2
    warmup_frac: float = 0.1
    min_lr_ratio: float = 0.01
    temperature: float = 0.2
    grad_clip: float = 1.0
    gradient_checkpointing: bool = False
    amp: bool = False

    # Infrastructure
    seed: int = 1337
    num_workers: int = 0
    device: str | None = None
    output_dir: str = "artifacts/embedder"
    run_name: str = "mirage-emb"
    wandb: bool = False
    log_every: int = 10


# ---------------------------------------------------------------------------
# Logging (wandb or CSV)
# ---------------------------------------------------------------------------


class MetricLogger:
    """Log scalars to Weights & Biases if available, else to a CSV file.

    The spec allows "wandb or CSV": we prefer wandb when the user opts in and the
    package imports, and always also write a CSV so a run is never lost. The CSV
    accumulates a union of all keys seen, written on :meth:`close`.
    """

    def __init__(
        self,
        output_dir: Path,
        run_name: str,
        use_wandb: bool,
        config: dict[str, Any],
    ) -> None:
        self.csv_path = output_dir / f"{run_name}_metrics.csv"
        self._rows: list[dict[str, Any]] = []
        self._wandb = None
        if use_wandb:
            try:
                import wandb  # type: ignore

                wandb.init(project="mirage-embeddings", name=run_name, config=config)
                self._wandb = wandb
            except Exception as exc:  # pragma: no cover - optional dependency
                print(f"[logger] wandb unavailable ({exc}); falling back to CSV only.")

    def log(self, metrics: dict[str, Any], step: int) -> None:
        row = {"step": step, **metrics}
        self._rows.append(row)
        if self._wandb is not None:
            self._wandb.log(metrics, step=step)

    def close(self) -> None:
        if self._rows:
            keys: list[str] = ["step"]
            for row in self._rows:
                for k in row:
                    if k not in keys:
                        keys.append(k)
            with self.csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=keys)
                writer.writeheader()
                writer.writerows(self._rows)
            print(f"[logger] wrote metrics -> {self.csv_path}")
        if self._wandb is not None:
            self._wandb.finish()


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------


def _load_sessions(cfg: TrainConfig) -> list[Session]:
    """Load real Cowrie sessions, or generate a synthetic corpus for smoke tests."""
    loader = SessionLoader(min_commands=cfg.min_commands)
    if cfg.synthetic:
        from ..data.synthetic import write_synthetic_log

        tmp_dir = Path(tempfile.mkdtemp(prefix="mirage_synth_"))
        log_path = tmp_dir / "synthetic_cowrie.json"
        write_synthetic_log(log_path, n_sessions=cfg.synthetic_sessions)
        return loader.load_file(log_path)
    if not cfg.input:
        raise ValueError("provide --input <cowrie dir/file> or use --synthetic")
    path = Path(cfg.input)
    if path.is_dir():
        return loader.load_dir(path, pattern=cfg.pattern)
    return loader.load_file(path)


def _split_sessions(
    sessions: list[Session], val_frac: float, seed: int
) -> tuple[list[Session], list[Session]]:
    """Shuffle and split sessions into train / val by ``val_frac``."""
    rng = random.Random(seed)
    order = list(range(len(sessions)))
    rng.shuffle(order)
    n_val = max(1, int(round(len(sessions) * val_frac)))
    val_idx = set(order[:n_val])
    train = [s for i, s in enumerate(sessions) if i not in val_idx]
    val = [s for i, s in enumerate(sessions) if i in val_idx]
    return train, val


def _seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


# ---------------------------------------------------------------------------
# Train / eval steps
# ---------------------------------------------------------------------------


def _run_epoch(
    model: SessionEmbedder,
    loader: DataLoader,
    criterion: NTXentLoss,
    device: torch.device,
    optimizer: torch.optim.Optimizer | None,
    scheduler: Any | None,
    scaler: torch.cuda.amp.GradScaler | None,
    cfg: TrainConfig,
    logger: MetricLogger | None,
    global_step: int,
    split: str,
) -> tuple[float, dict[str, float], int]:
    """Run one epoch (train if ``optimizer`` is given, else eval). Returns the
    mean loss, the last diagnostic metrics, and the updated global step."""
    is_train = optimizer is not None
    model.train(is_train)
    total_loss = 0.0
    n_batches = 0
    last_metrics: dict[str, float] = {}

    grad_context = torch.enable_grad() if is_train else torch.no_grad()
    with grad_context:
        for view1, view2 in loader:
            view1 = view1.to(device)
            view2 = view2.to(device)

            use_amp = cfg.amp and device.type == "cuda"
            with torch.autocast(device_type=device.type, enabled=use_amp):
                out1 = model(view1.input_ids, view1.timing, view1.attention_mask)
                out2 = model(view2.input_ids, view2.timing, view2.attention_mask)
                loss = criterion(out1.pooled, out2.pooled)

            if is_train:
                optimizer.zero_grad(set_to_none=True)
                if scaler is not None:
                    scaler.scale(loss).backward()
                    scaler.unscale_(optimizer)
                    torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip)
                    scaler.step(optimizer)
                    scaler.update()
                else:
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip)
                    optimizer.step()
                if scheduler is not None:
                    scheduler.step()
                global_step += 1

            batch_loss = float(loss.detach().item())
            total_loss += batch_loss
            n_batches += 1

            last_metrics = {
                f"{split}/loss": batch_loss,
                f"{split}/alignment": alignment_loss(out1.pooled, out2.pooled),
                f"{split}/uniformity": uniformity_loss(
                    torch.cat([out1.pooled, out2.pooled], dim=0)
                ),
            }
            if is_train:
                last_metrics["lr"] = optimizer.param_groups[0]["lr"]
                if logger is not None and global_step % cfg.log_every == 0:
                    logger.log(last_metrics, step=global_step)

    mean_loss = total_loss / max(1, n_batches)
    return mean_loss, last_metrics, global_step


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def train(cfg: TrainConfig) -> dict[str, Any]:
    """Run the full training procedure and return a summary dict."""
    _seed_everything(cfg.seed)
    device = torch.device(
        cfg.device or ("cuda" if torch.cuda.is_available() else "cpu")
    )
    output_dir = Path(cfg.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # -- Data ---------------------------------------------------------------
    sessions = _load_sessions(cfg)
    if len(sessions) < 4:
        raise ValueError(f"need >=4 sessions to train; loaded {len(sessions)}")
    train_sessions, val_sessions = _split_sessions(sessions, cfg.val_frac, cfg.seed)

    tokenizer = CommandTokenizer(
        TokenizerConfig(mode=cfg.tokenizer_mode, top_k=cfg.top_k)
    ).fit(train_sessions)
    tokenizer.save(output_dir / "tokenizer")

    train_ds = SessionDataset(
        train_sessions, tokenizer, cfg.max_length, cfg.standardize_timing
    )
    val_ds = SessionDataset(
        val_sessions, tokenizer, cfg.max_length, cfg.standardize_timing
    )
    collate = ContrastiveCollator(tokenizer, AugmentConfig())
    train_loader = DataLoader(
        train_ds,
        batch_size=cfg.batch_size,
        shuffle=True,
        drop_last=True,
        num_workers=cfg.num_workers,
        collate_fn=collate,
    )
    val_loader = DataLoader(
        val_ds,
        batch_size=cfg.batch_size,
        shuffle=False,
        drop_last=True,
        num_workers=cfg.num_workers,
        collate_fn=collate,
    )

    # -- Model --------------------------------------------------------------
    model_cfg = SessionEmbedderConfig(
        vocab_size=tokenizer.vocab_size,
        d_model=cfg.d_model,
        n_layers=cfg.n_layers,
        n_heads=cfg.n_heads,
        dropout=cfg.dropout,
        embedding_dim=cfg.embedding_dim,
        pad_id=tokenizer.pad_id,
        max_len=cfg.max_length + 8,  # headroom for bos/eos
        use_timing=cfg.use_timing,
    )
    model = SessionEmbedder(model_cfg).to(device)
    if cfg.gradient_checkpointing:
        model.gradient_checkpointing_enable()

    criterion = NTXentLoss(temperature=cfg.temperature)
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay
    )
    steps_per_epoch = max(1, len(train_loader))
    total_steps = steps_per_epoch * cfg.epochs
    warmup_steps = int(round(total_steps * cfg.warmup_frac))
    scheduler = cosine_warmup_schedule(
        optimizer, warmup_steps, total_steps, cfg.min_lr_ratio
    )
    scaler = (
        torch.cuda.amp.GradScaler()
        if (cfg.amp and device.type == "cuda")
        else None
    )

    logger = MetricLogger(output_dir, cfg.run_name, cfg.wandb, asdict(cfg))
    print(
        f"[train] device={device} sessions={len(sessions)} "
        f"(train={len(train_sessions)} val={len(val_sessions)}) "
        f"vocab={tokenizer.vocab_size} params={model.num_parameters():,} "
        f"steps/epoch={steps_per_epoch} total_steps={total_steps}"
    )

    # -- Loop ---------------------------------------------------------------
    best_val = math.inf
    global_step = 0
    history: list[dict[str, float]] = []
    for epoch in range(1, cfg.epochs + 1):
        train_loss, _, global_step = _run_epoch(
            model, train_loader, criterion, device, optimizer,
            scheduler, scaler, cfg, logger, global_step, "train",
        )
        val_loss, val_metrics, _ = _run_epoch(
            model, val_loader, criterion, device, None,
            None, None, cfg, None, global_step, "val",
        )
        epoch_metrics = {
            "epoch": epoch,
            "train/epoch_loss": train_loss,
            "val/epoch_loss": val_loss,
            **val_metrics,
        }
        history.append(epoch_metrics)
        logger.log(epoch_metrics, step=global_step)
        print(
            f"[epoch {epoch:3d}/{cfg.epochs}] "
            f"train_loss={train_loss:.4f} val_loss={val_loss:.4f} "
            f"val_align={val_metrics.get('val/alignment', float('nan')):.4f} "
            f"val_unif={val_metrics.get('val/uniformity', float('nan')):.4f}"
        )

        if val_loss < best_val:
            best_val = val_loss
            _save_checkpoint(model, model_cfg, output_dir / "best.pt")

    _save_checkpoint(model, model_cfg, output_dir / "last.pt")
    logger.close()
    (output_dir / "history.json").write_text(
        json.dumps(history, indent=2), encoding="utf-8"
    )

    return {
        "best_val_loss": best_val,
        "final_train_loss": history[-1]["train/epoch_loss"] if history else math.nan,
        "epochs": cfg.epochs,
        "output_dir": str(output_dir),
        "n_sessions": len(sessions),
        "vocab_size": tokenizer.vocab_size,
        "params": model.num_parameters(),
    }


def _save_checkpoint(
    model: SessionEmbedder, model_cfg: SessionEmbedderConfig, path: Path
) -> None:
    """Persist model weights plus the config needed to rebuild the architecture."""
    torch.save(
        {"state_dict": model.state_dict(), "config": asdict(model_cfg)}, path
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="Cowrie log file or directory.")
    src.add_argument(
        "--synthetic", action="store_true",
        help="Train on a freshly generated synthetic corpus (smoke test).",
    )
    p.add_argument("--synthetic-sessions", type=int, default=800)
    p.add_argument("--pattern", default="*.json*")
    p.add_argument("--min-commands", type=int, default=2)
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--val-frac", type=float, default=0.1)
    p.add_argument("--tokenizer-mode", choices=["command", "full"], default="command")
    p.add_argument("--top-k", type=int, default=500)
    p.add_argument("--no-standardize-timing", action="store_true")

    p.add_argument("--d-model", type=int, default=128)
    p.add_argument("--n-layers", type=int, default=2)
    p.add_argument("--n-heads", type=int, default=4)
    p.add_argument("--dropout", type=float, default=0.1)
    p.add_argument("--embedding-dim", type=int, default=128)
    p.add_argument("--no-timing", action="store_true", help="Ablate timing channel.")

    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--batch-size", type=int, default=256)
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--weight-decay", type=float, default=1e-2)
    p.add_argument("--warmup-frac", type=float, default=0.1)
    p.add_argument("--min-lr-ratio", type=float, default=0.01)
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--grad-clip", type=float, default=1.0)
    p.add_argument("--gradient-checkpointing", action="store_true")
    p.add_argument("--amp", action="store_true")

    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--num-workers", type=int, default=0)
    p.add_argument("--device", default=None)
    p.add_argument("--output-dir", default="artifacts/embedder")
    p.add_argument("--run-name", default="mirage-emb")
    p.add_argument("--wandb", action="store_true")
    p.add_argument("--log-every", type=int, default=10)
    return p


def main(argv: list[str] | None = None) -> dict[str, Any]:
    """CLI entry point. Parses args into a :class:`TrainConfig` and trains."""
    args = _build_arg_parser().parse_args(argv)
    cfg = TrainConfig(
        input=args.input,
        synthetic=args.synthetic,
        synthetic_sessions=args.synthetic_sessions,
        pattern=args.pattern,
        min_commands=args.min_commands,
        max_length=args.max_length,
        val_frac=args.val_frac,
        tokenizer_mode=args.tokenizer_mode,
        top_k=args.top_k,
        standardize_timing=not args.no_standardize_timing,
        d_model=args.d_model,
        n_layers=args.n_layers,
        n_heads=args.n_heads,
        dropout=args.dropout,
        embedding_dim=args.embedding_dim,
        use_timing=not args.no_timing,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        weight_decay=args.weight_decay,
        warmup_frac=args.warmup_frac,
        min_lr_ratio=args.min_lr_ratio,
        temperature=args.temperature,
        grad_clip=args.grad_clip,
        gradient_checkpointing=args.gradient_checkpointing,
        amp=args.amp,
        seed=args.seed,
        num_workers=args.num_workers,
        device=args.device,
        output_dir=args.output_dir,
        run_name=args.run_name,
        wandb=args.wandb,
        log_every=args.log_every,
    )
    summary = train(cfg)
    print(json.dumps(summary, indent=2, default=str))
    return summary


if __name__ == "__main__":  # pragma: no cover
    main()
