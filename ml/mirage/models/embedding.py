"""Multi-modal session embedding -- the core of MIRAGE Phase 2.

Overview
--------
:class:`SessionEmbedder` turns one attacker session into

1. a **128-d static behavioral vector** (mean-pooled), used for clustering,
   re-identification (Phase 3) and as the contrastive head's input; and
2. the **full sequence of contextualized hidden states**, consumed by
   :class:`~mirage.models.trajectory.TemporalTrajectoryAnalyzer`.

Why this is not a standard NLP encoder
--------------------------------------
A session is a **marked temporal point process** (see ``mirage.data.schema``):
each command is an event with a *mark* (which command) and an *event time*
(when). The temporal structure is not metadata -- the inter-command interval
(ICI) distribution separates metronomic scripts from bursty humans as cleanly as
the command verbs do (Phase 1's thesis). We therefore feed two *parallel,
aligned* channels into the encoder:

* the **command-token channel** -- the mark, via an embedding lookup;
* the **log-ICI timing channel** -- the event-time covariate, projected into the
  model space and fused additively at the input.

This is the same design CEBRA uses for behavior-aware neural embeddings: a
primary signal plus an **auxiliary continuous covariate** that conditions the
representation. Here the log-ICI is that covariate. Fusing it at the input (not
concatenating a late feature) lets self-attention reason jointly about *what*
was typed and *how fast*, which is what makes same-tool sessions collapse
together regardless of the exact arguments they carried.

Architecture (matches the Phase-2 spec)
---------------------------------------
    token ids  ->  embedding lookup (d_model, padding_idx)  -.
                                                              +--> + sinusoidal
    log-ICI    ->  timing MLP (1 -> d_model)  ------------------'   positional
                                                                    encoding
        -> 2-layer, 4-head Transformer encoder (pre-norm, padding-masked)
        -> masked mean pool over valid positions  -> 128-d static vector
        -> (also) the full [B, L, d_model] hidden-state sequence

``d_model`` defaults to 128 so the pooled vector *is* the 128-d embedding with no
extra projection. Gradient checkpointing (per encoder layer) keeps very long
sessions within memory; it is applied only in training and only when enabled.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import torch
import torch.nn as nn
from torch.utils.checkpoint import checkpoint

__all__ = [
    "SessionEmbedderConfig",
    "SessionEmbedderOutput",
    "SinusoidalPositionalEncoding",
    "SessionEmbedder",
]


@dataclass
class SessionEmbedderConfig:
    """Configuration for :class:`SessionEmbedder`.

    Attributes:
        vocab_size: Size of the tokenizer vocabulary (including special tokens).
            Must match ``CommandTokenizer.vocab_size``.
        d_model: Transformer width. Defaults to 128 so the pooled embedding is
            the 128-d vector with no extra projection.
        n_layers: Number of Transformer encoder layers (spec: 2).
        n_heads: Number of attention heads (spec: 4). ``d_model`` must be
            divisible by this.
        dim_feedforward: Inner width of each layer's MLP. Defaults to
            ``4 * d_model``.
        dropout: Dropout probability used in embeddings and the encoder.
        embedding_dim: Final embedding dimensionality (spec: 128). If it differs
            from ``d_model`` a linear projection is applied after pooling.
        pad_id: Vocabulary id of ``<pad>``; rows are masked out of attention and
            pooling, and the embedding for this id is held at zero.
        max_len: Maximum sequence length the positional encoding supports. Longer
            sessions are truncated by the data pipeline, not here.
        timing_hidden: Hidden width of the timing MLP that lifts the scalar
            log-ICI to ``d_model``.
        scale_embeddings: If ``True``, scale token embeddings by ``sqrt(d_model)``
            (the standard Transformer convention) before fusion.
        use_timing: If ``False``, ablate the timing channel entirely (token-only
            baseline for the paper). The forward signature is unchanged.
    """

    vocab_size: int
    d_model: int = 128
    n_layers: int = 2
    n_heads: int = 4
    dim_feedforward: int | None = None
    dropout: float = 0.1
    embedding_dim: int = 128
    pad_id: int = 0
    max_len: int = 1024
    timing_hidden: int = 64
    scale_embeddings: bool = True
    use_timing: bool = True

    def __post_init__(self) -> None:
        if self.d_model % self.n_heads != 0:
            raise ValueError(
                f"d_model={self.d_model} must be divisible by n_heads={self.n_heads}"
            )
        if self.dim_feedforward is None:
            self.dim_feedforward = 4 * self.d_model


@dataclass
class SessionEmbedderOutput:
    """Outputs of a :class:`SessionEmbedder` forward pass.

    Attributes:
        pooled: ``[B, embedding_dim]`` -- the masked-mean-pooled static behavioral
            vector. This is the session embedding used downstream.
        hidden_states: ``[B, L, d_model]`` -- the per-position contextualized
            states. Row ``i`` is the model's state *after attending over the whole
            session* at command position ``i``; this is the raw material for
            trajectory analysis (the analogue of a neural population state at each
            time bin).
        attention_mask: ``[B, L]`` -- ``1`` for real positions, ``0`` for padding,
            passed through so downstream code never has to re-derive it.
    """

    pooled: torch.Tensor
    hidden_states: torch.Tensor
    attention_mask: torch.Tensor


class SinusoidalPositionalEncoding(nn.Module):
    """Classic fixed sinusoidal positional encoding (Vaswani et al., 2017).

    Encodes ordinal command position. Note this is deliberately *separate* from
    the timing channel: position answers "which command index" while the log-ICI
    channel answers "how long since the previous command". Both matter -- a tool
    and a human can issue the same 5th command but with very different ICIs.
    """

    def __init__(self, d_model: int, max_len: int) -> None:
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float32).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2, dtype=torch.float32)
            * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        # [1, max_len, d_model] -- registered as a buffer so it moves with .to().
        self.register_buffer("pe", pe.unsqueeze(0), persistent=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Add positional encoding to ``x`` of shape ``[B, L, d_model]``."""
        seq_len = x.size(1)
        if seq_len > self.pe.size(1):
            raise ValueError(
                f"sequence length {seq_len} exceeds positional-encoding "
                f"capacity {self.pe.size(1)}; raise SessionEmbedderConfig.max_len"
            )
        return x + self.pe[:, :seq_len]


class SessionEmbedder(nn.Module):
    """Dual-channel Transformer encoder for attacker sessions.

    See the module docstring for the full rationale. The forward pass accepts the
    two aligned channels emitted by ``CommandTokenizer.encode`` and returns a
    :class:`SessionEmbedderOutput`.

    Args:
        config: A :class:`SessionEmbedderConfig`.
    """

    def __init__(self, config: SessionEmbedderConfig) -> None:
        super().__init__()
        self.config = config

        # -- Mark channel: command-token embedding -------------------------
        self.token_embedding = nn.Embedding(
            config.vocab_size, config.d_model, padding_idx=config.pad_id
        )
        self.embed_scale = math.sqrt(config.d_model) if config.scale_embeddings else 1.0

        # -- Event-time channel: log-ICI -> d_model ------------------------
        # A small MLP lifts the scalar log-ICI to the model width so attention
        # can mix timing with content. Disabled (held at 0) under the token-only
        # ablation so the rest of the graph is identical.
        if config.use_timing:
            self.timing_encoder: nn.Module = nn.Sequential(
                nn.Linear(1, config.timing_hidden),
                nn.GELU(),
                nn.Linear(config.timing_hidden, config.d_model),
            )
        else:
            self.timing_encoder = None  # type: ignore[assignment]

        self.positional_encoding = SinusoidalPositionalEncoding(
            config.d_model, config.max_len
        )
        self.input_dropout = nn.Dropout(config.dropout)

        # -- Encoder stack (kept as a ModuleList so we can checkpoint layer-
        #    by-layer; nn.TransformerEncoder hides the per-layer boundary). ---
        self.layers = nn.ModuleList(
            nn.TransformerEncoderLayer(
                d_model=config.d_model,
                nhead=config.n_heads,
                dim_feedforward=config.dim_feedforward,
                dropout=config.dropout,
                activation="gelu",
                batch_first=True,
                norm_first=True,  # pre-norm: more stable for short, deep-ish stacks
            )
            for _ in range(config.n_layers)
        )
        self.final_norm = nn.LayerNorm(config.d_model)

        # -- Optional projection if embedding_dim != d_model ----------------
        if config.embedding_dim != config.d_model:
            self.output_projection: nn.Module = nn.Linear(
                config.d_model, config.embedding_dim
            )
        else:
            self.output_projection = nn.Identity()

        self.gradient_checkpointing = False
        self._init_parameters()

    # -- Initialization -----------------------------------------------------

    def _init_parameters(self) -> None:
        """Xavier-init the linears; keep the pad embedding row at zero."""
        nn.init.normal_(self.token_embedding.weight, mean=0.0, std=self.config.d_model ** -0.5)
        with torch.no_grad():
            self.token_embedding.weight[self.config.pad_id].fill_(0.0)

    # -- Public toggles -----------------------------------------------------

    def gradient_checkpointing_enable(self) -> None:
        """Trade compute for memory on long sessions (training only)."""
        self.gradient_checkpointing = True

    def gradient_checkpointing_disable(self) -> None:
        self.gradient_checkpointing = False

    # -- Forward ------------------------------------------------------------

    def _embed_inputs(
        self, input_ids: torch.Tensor, timing: torch.Tensor
    ) -> torch.Tensor:
        """Fuse the two channels and add positional encoding.

        Args:
            input_ids: ``[B, L]`` long tensor of vocabulary ids.
            timing: ``[B, L]`` float tensor of (log-scaled) ICIs, aligned 1:1.

        Returns:
            ``[B, L, d_model]`` input representation.
        """
        x = self.token_embedding(input_ids) * self.embed_scale
        if self.timing_encoder is not None:
            # [B, L] -> [B, L, 1] -> [B, L, d_model]
            x = x + self.timing_encoder(timing.unsqueeze(-1))
        x = self.positional_encoding(x)
        return self.input_dropout(x)

    def _run_layer(
        self,
        layer: nn.Module,
        x: torch.Tensor,
        key_padding_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Run one encoder layer, checkpointing it when enabled in training."""
        if self.gradient_checkpointing and self.training:
            # use_reentrant=False is the modern, mask-friendly checkpoint path.
            return checkpoint(
                layer, x, None, key_padding_mask, use_reentrant=False
            )
        return layer(x, src_key_padding_mask=key_padding_mask)

    def forward(
        self,
        input_ids: torch.Tensor,
        timing: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> SessionEmbedderOutput:
        """Encode a padded batch of dual-channel sessions.

        Args:
            input_ids: ``[B, L]`` long tensor of token ids.
            timing: ``[B, L]`` float tensor of log-ICI values, aligned with
                ``input_ids`` (the ``EncodedSession.timing`` channel).
            attention_mask: ``[B, L]`` tensor, ``1`` for real positions and ``0``
                for padding (the ``EncodedSession.attention_mask``).

        Returns:
            A :class:`SessionEmbedderOutput` with the pooled 128-d vector, the
            full hidden-state sequence, and the attention mask.
        """
        if input_ids.dim() != 2:
            raise ValueError(f"input_ids must be [B, L]; got {tuple(input_ids.shape)}")
        attention_mask = attention_mask.to(dtype=input_ids.dtype)
        # nn.Transformer expects True == "ignore this position".
        key_padding_mask = attention_mask == 0

        x = self._embed_inputs(input_ids, timing.to(self.token_embedding.weight.dtype))
        for layer in self.layers:
            x = self._run_layer(layer, x, key_padding_mask)
        hidden_states = self.final_norm(x)

        pooled = self._masked_mean_pool(hidden_states, attention_mask)
        pooled = self.output_projection(pooled)

        return SessionEmbedderOutput(
            pooled=pooled,
            hidden_states=hidden_states,
            attention_mask=attention_mask,
        )

    # -- Pooling ------------------------------------------------------------

    @staticmethod
    def _masked_mean_pool(
        hidden_states: torch.Tensor, attention_mask: torch.Tensor
    ) -> torch.Tensor:
        """Mean-pool hidden states over valid (non-pad) positions.

        Args:
            hidden_states: ``[B, L, D]``.
            attention_mask: ``[B, L]`` with ``1`` for valid positions.

        Returns:
            ``[B, D]`` pooled representation. Sessions with no valid positions
            (degenerate, should not occur after the loader's ``min_commands``
            filter) pool to zeros rather than NaN.
        """
        mask = attention_mask.unsqueeze(-1).to(hidden_states.dtype)  # [B, L, 1]
        summed = (hidden_states * mask).sum(dim=1)  # [B, D]
        counts = mask.sum(dim=1).clamp(min=1.0)  # [B, 1]
        return summed / counts

    # -- Convenience --------------------------------------------------------

    @torch.no_grad()
    def embed(
        self,
        input_ids: torch.Tensor,
        timing: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """Return only the pooled 128-d embeddings (eval mode, no grad)."""
        was_training = self.training
        self.eval()
        try:
            out = self.forward(input_ids, timing, attention_mask)
        finally:
            self.train(was_training)
        return out.pooled

    def num_parameters(self, trainable_only: bool = True) -> int:
        """Count parameters (for the paper's model card)."""
        params = self.parameters()
        if trainable_only:
            return sum(p.numel() for p in params if p.requires_grad)
        return sum(p.numel() for p in params)
