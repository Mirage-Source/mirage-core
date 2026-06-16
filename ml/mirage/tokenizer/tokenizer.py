"""CommandTokenizer: dual-channel encoding of attacker sessions.

The tokenizer converts a :class:`~mirage.data.schema.Session` into two *aligned*
parallel channels that feed every downstream sequence model:

1. **Token channel** -- an integer id per command, drawn from a frequency-capped
   vocabulary (top-K commands; everything else -> ``<oov>``).
2. **Timing channel** -- a real value per command: the log-scaled inter-command
   interval (ICI) in milliseconds.

Why two channels, and why this matters (the thesis of MIRAGE's Phase 1):

    A session is a *marked temporal point process*. The token is the **mark**
    (which command) and the timing is the **event time** (when). Most prior
    honeypot ML throws timing away and models only the command sequence. But the
    ICI distribution is exactly an inter-spike-interval (ISI) distribution, and
    in neuroscience the ISI -- especially its regularity -- is one of the most
    discriminative single features you can compute about a spike train. Here it
    cleanly separates metronomic scripts from bursty humans. We therefore treat
    timing as a first-class, co-equal channel, not a side feature.

Two vocabulary modes (see :mod:`mirage.tokenizer.normalize`):
    * ``"command"``: token = command head verb (arguments stripped).
    * ``"full"``:    token = normalized, redacted full command line.

Serialization writes two files into a directory:
    * ``vocab.json``  -- token <-> id mapping.
    * ``config.json`` -- mode, special tokens, top_k, and corpus timing stats
      used for optional timing standardization.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from ..data.schema import Session
from .normalize import head_command, normalize_full

__all__ = ["TokenizerConfig", "EncodedSession", "CommandTokenizer"]

Mode = Literal["command", "full"]

# Reserved ids. Order is part of the on-disk contract; do not reorder.
PAD_TOKEN = "<pad>"
BOS_TOKEN = "<bos>"
EOS_TOKEN = "<eos>"
OOV_TOKEN = "<oov>"
SPECIAL_TOKENS: tuple[str, ...] = (PAD_TOKEN, BOS_TOKEN, EOS_TOKEN, OOV_TOKEN)


@dataclass
class TokenizerConfig:
    """Serializable tokenizer configuration.

    Attributes:
        mode: ``"command"`` (head verb) or ``"full"`` (normalized line).
        top_k: Number of corpus commands kept in the vocabulary (excludes the
            special tokens). The MIRAGE default is 500.
        add_bos: Prepend a ``<bos>`` token when encoding.
        add_eos: Append an ``<eos>`` token when encoding.
        timing_log_base: Base for the log transform of the ICI (``math.e`` =>
            natural log of ``1 + ms``).
        timing_mean: Corpus mean of the log-ICI, for optional standardization.
        timing_std: Corpus std of the log-ICI, for optional standardization.
        version: Schema version of the serialized artifacts.
    """

    mode: Mode = "command"
    top_k: int = 500
    add_bos: bool = True
    add_eos: bool = True
    timing_log_base: float = math.e
    timing_mean: float = 0.0
    timing_std: float = 1.0
    version: int = 1


@dataclass(slots=True)
class EncodedSession:
    """Aligned dual-channel encoding of a session.

    All list fields share the same length ``L`` (including any special tokens
    and padding). ``input_ids[i]`` and ``timing[i]`` describe the same step.

    Attributes:
        input_ids: Vocabulary ids, length ``L``.
        timing: Log-scaled (optionally standardized) ICI per step, length ``L``.
        attention_mask: ``1`` for real/special tokens, ``0`` for padding.
        length: Number of non-padding positions.
    """

    input_ids: list[int]
    timing: list[float]
    attention_mask: list[int]
    length: int


class CommandTokenizer:
    """Frequency-capped, dual-channel tokenizer for attacker sessions.

    Build a vocabulary from a corpus with :meth:`fit`, encode sessions with
    :meth:`encode`, and persist / restore with :meth:`save` / :meth:`load`.

    Args:
        config: Tokenizer configuration. A default :class:`TokenizerConfig` is
            used if omitted.
    """

    def __init__(self, config: TokenizerConfig | None = None) -> None:
        self.config = config or TokenizerConfig()
        self._token_to_id: dict[str, int] = {}
        self._id_to_token: list[str] = []
        self._install_specials()

    # -- Construction helpers ----------------------------------------------

    def _install_specials(self) -> None:
        """Seed the vocabulary with the reserved special tokens."""
        self._token_to_id = {tok: i for i, tok in enumerate(SPECIAL_TOKENS)}
        self._id_to_token = list(SPECIAL_TOKENS)

    def _normalize(self, raw: str) -> str:
        """Apply the configured normalization mode to a raw command line."""
        if self.config.mode == "command":
            return head_command(raw)
        return normalize_full(raw)

    # -- Public properties --------------------------------------------------

    @property
    def pad_id(self) -> int:
        return self._token_to_id[PAD_TOKEN]

    @property
    def bos_id(self) -> int:
        return self._token_to_id[BOS_TOKEN]

    @property
    def eos_id(self) -> int:
        return self._token_to_id[EOS_TOKEN]

    @property
    def oov_id(self) -> int:
        return self._token_to_id[OOV_TOKEN]

    @property
    def vocab_size(self) -> int:
        """Total vocabulary size, including special tokens."""
        return len(self._id_to_token)

    def __len__(self) -> int:
        return self.vocab_size

    # -- Fitting ------------------------------------------------------------

    def fit(self, sessions: Iterable[Session]) -> "CommandTokenizer":
        """Build the vocabulary and timing statistics from a corpus.

        Counts normalized commands across all sessions, keeps the ``top_k`` most
        frequent as the vocabulary, and computes the corpus mean/std of the
        log-ICI for optional timing standardization.

        Args:
            sessions: Iterable of sessions (consumed once).

        Returns:
            ``self``, for chaining.
        """
        counts: Counter[str] = Counter()
        log_icis: list[float] = []

        for session in sessions:
            for raw in session.raw_commands():
                token = self._normalize(raw)
                if token:
                    counts[token] += 1
            for delta in session.inter_command_deltas_ms():
                log_icis.append(self._log_ici(max(delta, 0)))

        self._install_specials()
        for token, _ in counts.most_common(self.config.top_k):
            if token not in self._token_to_id:
                self._token_to_id[token] = len(self._id_to_token)
                self._id_to_token.append(token)

        if log_icis:
            mean = sum(log_icis) / len(log_icis)
            var = sum((x - mean) ** 2 for x in log_icis) / len(log_icis)
            self.config.timing_mean = mean
            self.config.timing_std = math.sqrt(var) or 1.0

        return self

    # -- Timing transform ---------------------------------------------------

    def _log_ici(self, delta_ms: float) -> float:
        """Log-scale an inter-command interval (the log-ISI transform).

        Uses ``log(1 + delta_ms)`` so that a zero-delta step maps to ``0`` and
        the heavy right tail of think-pauses is compressed. The neuroscience
        rationale: ISIs are approximately log-normally distributed, so the log
        domain is where Gaussian-friendly models and distance metrics behave.
        """
        value = math.log1p(max(delta_ms, 0.0))
        base = self.config.timing_log_base
        if base != math.e:
            value /= math.log(base)
        return value

    def _maybe_standardize(self, log_ici: float, standardize: bool) -> float:
        if not standardize:
            return log_ici
        return (log_ici - self.config.timing_mean) / (self.config.timing_std or 1.0)

    # -- Encoding -----------------------------------------------------------

    def encode_command(self, raw: str) -> int:
        """Encode a single raw command line to its vocabulary id (``<oov>`` if
        out of vocabulary or empty)."""
        token = self._normalize(raw)
        if not token:
            return self.oov_id
        return self._token_to_id.get(token, self.oov_id)

    def encode(
        self,
        session: Session,
        max_length: int | None = None,
        pad_to: int | None = None,
        standardize_timing: bool = False,
    ) -> EncodedSession:
        """Encode a session into aligned token and timing channels.

        The timing for command ``i`` is the log-scaled ICI from command ``i-1``;
        the first command (and any special token) is assigned timing ``0`` in the
        log domain (standardized if requested). This keeps the two channels in
        exact 1:1 alignment, including special tokens and padding.

        Args:
            session: Session to encode.
            max_length: If set, truncate the *command* sequence to this many
                commands (special tokens are added on top, not counted here).
            pad_to: If set, right-pad both channels to this length with
                ``<pad>`` / ``0`` and a zeroed attention mask.
            standardize_timing: If ``True``, z-score the timing channel using the
                corpus statistics stored on the config.

        Returns:
            An :class:`EncodedSession`.
        """
        raws = session.raw_commands()
        offsets = [c.ms_offset for c in session.commands]
        if max_length is not None:
            raws = raws[:max_length]
            offsets = offsets[:max_length]

        ids: list[int] = []
        timing: list[float] = []

        if self.config.add_bos:
            ids.append(self.bos_id)
            timing.append(self._maybe_standardize(0.0, standardize_timing))

        prev_offset: int | None = None
        for raw, offset in zip(raws, offsets):
            ids.append(self.encode_command(raw))
            delta = 0 if prev_offset is None else max(offset - prev_offset, 0)
            log_ici = self._log_ici(delta)
            timing.append(self._maybe_standardize(log_ici, standardize_timing))
            prev_offset = offset

        if self.config.add_eos:
            ids.append(self.eos_id)
            timing.append(self._maybe_standardize(0.0, standardize_timing))

        length = len(ids)
        attention_mask = [1] * length

        if pad_to is not None and length < pad_to:
            pad_n = pad_to - length
            ids.extend([self.pad_id] * pad_n)
            timing.extend([0.0] * pad_n)
            attention_mask.extend([0] * pad_n)

        return EncodedSession(
            input_ids=ids,
            timing=timing,
            attention_mask=attention_mask,
            length=length,
        )

    def encode_batch(
        self,
        sessions: Sequence[Session],
        max_length: int | None = None,
        standardize_timing: bool = False,
    ) -> list[EncodedSession]:
        """Encode a batch of sessions, padding all to the batch's max length."""
        encoded = [
            self.encode(s, max_length=max_length, standardize_timing=standardize_timing)
            for s in sessions
        ]
        if not encoded:
            return encoded
        batch_len = max(e.length for e in encoded)
        # Re-encode with padding now that we know the batch width.
        return [
            self.encode(
                s,
                max_length=max_length,
                pad_to=batch_len,
                standardize_timing=standardize_timing,
            )
            for s in sessions
        ]

    def decode(self, ids: Iterable[int], skip_special: bool = True) -> list[str]:
        """Map a sequence of ids back to tokens (for inspection / debugging)."""
        specials = set(range(len(SPECIAL_TOKENS)))
        out: list[str] = []
        for i in ids:
            if skip_special and i in specials:
                continue
            if 0 <= i < len(self._id_to_token):
                out.append(self._id_to_token[i])
            else:
                out.append(OOV_TOKEN)
        return out

    # -- Serialization ------------------------------------------------------

    def save(self, directory: str | Path) -> None:
        """Persist ``vocab.json`` and ``config.json`` to ``directory``."""
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        vocab = {tok: i for i, tok in enumerate(self._id_to_token)}
        (out_dir / "vocab.json").write_text(
            json.dumps(vocab, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (out_dir / "config.json").write_text(
            json.dumps(asdict(self.config), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, directory: str | Path) -> "CommandTokenizer":
        """Restore a tokenizer previously written by :meth:`save`."""
        in_dir = Path(directory)
        config_data: dict[str, Any] = json.loads(
            (in_dir / "config.json").read_text(encoding="utf-8")
        )
        config = TokenizerConfig(**config_data)
        tok = cls(config)

        vocab: dict[str, int] = json.loads(
            (in_dir / "vocab.json").read_text(encoding="utf-8")
        )
        # Rebuild id<->token tables in id order to preserve the contract.
        id_to_token = [""] * len(vocab)
        for token, idx in vocab.items():
            id_to_token[idx] = token
        tok._id_to_token = id_to_token
        tok._token_to_id = dict(vocab)
        return tok
