"""Real-time attacker classifier with calibrated confidence.

A small MLP over the behavioural feature vector (optionally concatenated with the
128-d Phase-2 embedding) that predicts one of the four attacker classes. It is
trained to **distil the weak labels** (``mirage.intel.taxonomy.weak_label``) into a
smooth model that generalises across sessions and -- crucially for a threat-intel
product -- emits a **calibrated confidence**.

Calibration matters here. A raw softmax is over-confident, so a "0.97 APT" would
be untrustworthy. We apply **temperature scaling** (Guo et al., 2017): after
training, a single scalar ``T`` is fit on a held-out split to minimise NLL, and
inference divides the logits by ``T``. The reported confidence then actually means
what it says -- an analyst can threshold on it. We report Expected Calibration
Error (ECE) before and after to show the effect.

Feature standardisation (z-scoring per feature) is learned on the training split
and stored as buffers, so the saved model is self-contained: feed it a raw feature
vector and it normalises internally.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .features import IntelFeatures, extract_features
from .ingest import ProductionSession
from .taxonomy import ATTACKER_CLASSES, AttackerClass

__all__ = [
    "ClassifierConfig",
    "SessionClassifier",
    "ClassificationResult",
    "expected_calibration_error",
    "train_classifier",
    "classify",
]


@dataclass
class ClassifierConfig:
    """Configuration for :class:`SessionClassifier`.

    Attributes:
        input_dim: Behavioural feature-vector width (``len(FEATURE_NAMES)``).
        hidden_dim: Hidden width of the MLP.
        n_classes: Number of attacker classes (4).
        dropout: Dropout probability.
        embedding_dim: If ``> 0``, the model also consumes a behavioural embedding
            of this width, concatenated to the features (set 0 for features-only,
            the default / degraded mode).
    """

    input_dim: int
    hidden_dim: int = 64
    n_classes: int = len(ATTACKER_CLASSES)
    dropout: float = 0.1
    embedding_dim: int = 0


@dataclass
class ClassificationResult:
    """Output of classifying one session.

    Attributes:
        attacker_class: The predicted class label.
        confidence: Calibrated probability of the predicted class in ``[0, 1]``.
        probabilities: Full class-probability mapping.
    """

    attacker_class: AttackerClass
    confidence: float
    probabilities: dict[str, float]


class SessionClassifier(nn.Module):
    """Calibrated MLP attacker classifier over behavioural features (+ embedding)."""

    def __init__(self, config: ClassifierConfig) -> None:
        super().__init__()
        self.config = config
        in_dim = config.input_dim + config.embedding_dim
        self.net = nn.Sequential(
            nn.Linear(in_dim, config.hidden_dim),
            nn.ReLU(inplace=True),
            nn.Dropout(config.dropout),
            nn.Linear(config.hidden_dim, config.hidden_dim),
            nn.ReLU(inplace=True),
            nn.Linear(config.hidden_dim, config.n_classes),
        )
        # Feature standardisation (set by `train_classifier`) and temperature
        # (set by calibration) are buffers so the model is self-contained.
        self.register_buffer("feature_mean", torch.zeros(config.input_dim))
        self.register_buffer("feature_std", torch.ones(config.input_dim))
        self.register_buffer("temperature", torch.ones(()))
        self.class_names: tuple[str, ...] = ATTACKER_CLASSES

    def _standardize(self, features: torch.Tensor) -> torch.Tensor:
        return (features - self.feature_mean) / self.feature_std.clamp(min=1e-6)

    def forward(
        self, features: torch.Tensor, embedding: torch.Tensor | None = None
    ) -> torch.Tensor:
        """Return raw (un-temperature-scaled) logits ``[B, n_classes]``."""
        x = self._standardize(features)
        if self.config.embedding_dim > 0:
            if embedding is None:
                raise ValueError("model expects an embedding but none was given")
            x = torch.cat([x, embedding], dim=-1)
        return self.net(x)

    def predict_proba(
        self, features: torch.Tensor, embedding: torch.Tensor | None = None
    ) -> torch.Tensor:
        """Temperature-scaled class probabilities ``[B, n_classes]``."""
        logits = self.forward(features, embedding)
        return F.softmax(logits / self.temperature.clamp(min=1e-3), dim=-1)


def expected_calibration_error(
    probs: np.ndarray, labels: np.ndarray, n_bins: int = 10
) -> float:
    """Expected Calibration Error (lower == better calibrated).

    Bins predictions by their top-class confidence and measures the gap between
    confidence and accuracy within each bin, weighted by bin population.
    """
    confidences = probs.max(axis=1)
    predictions = probs.argmax(axis=1)
    accuracies = (predictions == labels).astype(np.float64)
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(labels)
    for lo, hi in zip(bins[:-1], bins[1:]):
        in_bin = (confidences > lo) & (confidences <= hi)
        if in_bin.sum() > 0:
            ece += (in_bin.sum() / n) * abs(
                accuracies[in_bin].mean() - confidences[in_bin].mean()
            )
    return float(ece)


def _fit_temperature(logits: torch.Tensor, labels: torch.Tensor) -> float:
    """Fit the temperature ``T`` that minimises validation NLL (Guo et al., 2017)."""
    log_t = torch.zeros(1, requires_grad=True)  # T = exp(log_t) > 0
    optimizer = torch.optim.LBFGS([log_t], lr=0.1, max_iter=60)

    def closure() -> torch.Tensor:
        optimizer.zero_grad()
        loss = F.cross_entropy(logits / log_t.exp(), labels)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(log_t.exp().item())


def train_classifier(
    features: np.ndarray,
    labels: np.ndarray,
    sample_weight: np.ndarray | None = None,
    config: ClassifierConfig | None = None,
    epochs: int = 200,
    lr: float = 1e-3,
    weight_decay: float = 1e-4,
    val_frac: float = 0.25,
    seed: int = 0,
    embeddings: np.ndarray | None = None,
) -> tuple[SessionClassifier, dict[str, float]]:
    """Train the classifier on weak labels and calibrate its confidence.

    Args:
        features: ``[N, D]`` behavioural feature matrix.
        labels: ``[N]`` integer class indices (into :data:`ATTACKER_CLASSES`).
        sample_weight: Optional ``[N]`` per-example weight (e.g. weak-label
            confidence).
        config: Model config; inferred (features-only) from shapes if omitted.
        embeddings: Optional ``[N, E]`` behavioural embeddings to concatenate.
        Remaining args: standard optimisation knobs.

    Returns:
        ``(model, metrics)`` where metrics include val accuracy, macro-F1, and ECE
        before/after temperature calibration.
    """
    rng = np.random.default_rng(seed)
    torch.manual_seed(seed)
    n, d = features.shape
    if config is None:
        config = ClassifierConfig(
            input_dim=d, embedding_dim=(embeddings.shape[1] if embeddings is not None else 0)
        )

    # Train/val split.
    perm = rng.permutation(n)
    n_val = max(1, int(round(n * val_frac)))
    val_idx, train_idx = perm[:n_val], perm[n_val:]

    X = torch.tensor(features, dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.long)
    emb = torch.tensor(embeddings, dtype=torch.float32) if embeddings is not None else None
    w = torch.tensor(
        sample_weight if sample_weight is not None else np.ones(n), dtype=torch.float32
    )

    model = SessionClassifier(config)
    # Standardisation from the training split only.
    train_feats = X[train_idx]
    model.feature_mean.copy_(train_feats.mean(dim=0))
    model.feature_std.copy_(train_feats.std(dim=0).clamp(min=1e-6))

    # Class weights counter the bot-dominated imbalance.
    class_counts = np.bincount(labels[train_idx], minlength=config.n_classes) + 1.0
    class_w = torch.tensor(class_counts.sum() / class_counts, dtype=torch.float32)

    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits = model(X[train_idx], emb[train_idx] if emb is not None else None)
        per = F.cross_entropy(logits, y[train_idx], weight=class_w, reduction="none")
        loss = (per * w[train_idx]).mean()
        loss.backward()
        optimizer.step()

    # Validation logits (pre-calibration).
    model.eval()
    with torch.no_grad():
        val_logits = model(X[val_idx], emb[val_idx] if emb is not None else None)
        pre_probs = F.softmax(val_logits, dim=-1).numpy()
        val_pred = pre_probs.argmax(axis=1)
        val_true = labels[val_idx]

    acc = float((val_pred == val_true).mean())
    macro_f1 = _macro_f1(val_true, val_pred, config.n_classes)
    ece_before = expected_calibration_error(pre_probs, val_true)

    # Temperature scaling on the validation split.
    temperature = _fit_temperature(val_logits, y[val_idx])
    model.temperature.fill_(temperature)
    with torch.no_grad():
        post_probs = F.softmax(val_logits / temperature, dim=-1).numpy()
    ece_after = expected_calibration_error(post_probs, val_true)

    metrics = {
        "val_accuracy": acc,
        "val_macro_f1": macro_f1,
        "ece_before": ece_before,
        "ece_after": ece_after,
        "temperature": temperature,
        "n_train": int(len(train_idx)),
        "n_val": int(len(val_idx)),
    }
    return model, metrics


def _macro_f1(y_true: np.ndarray, y_pred: np.ndarray, n_classes: int) -> float:
    """Unweighted mean per-class F1 (robust to class imbalance)."""
    f1s = []
    for c in range(n_classes):
        tp = int(((y_pred == c) & (y_true == c)).sum())
        fp = int(((y_pred == c) & (y_true != c)).sum())
        fn = int(((y_pred != c) & (y_true == c)).sum())
        if tp == 0:
            f1s.append(0.0)
            continue
        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1s.append(2 * precision * recall / (precision + recall))
    return float(np.mean(f1s)) if f1s else 0.0


@torch.no_grad()
def classify(
    model: SessionClassifier,
    prod: ProductionSession,
    features: IntelFeatures | None = None,
    embedding: np.ndarray | None = None,
) -> ClassificationResult:
    """Classify one session in real time, returning a calibrated result."""
    feats = features or extract_features(prod)
    model.eval()
    x = torch.tensor(feats.vector, dtype=torch.float32).unsqueeze(0)
    emb = (
        torch.tensor(embedding, dtype=torch.float32).unsqueeze(0)
        if embedding is not None
        else None
    )
    probs = model.predict_proba(x, emb).squeeze(0).numpy()
    idx = int(probs.argmax())
    return ClassificationResult(
        attacker_class=model.class_names[idx],  # type: ignore[index]
        confidence=float(probs[idx]),
        probabilities={name: float(p) for name, p in zip(model.class_names, probs)},
    )
