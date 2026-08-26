

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

# Reserved ids. Order is part of the on-disk contract; do not reorder --
# DUR_TOKEN was added after the first four and must stay last so an existing
# saved vocab.json's ids for pad/bos/eos/oov never shift.
PAD_TOKEN = "<pad>"
BOS_TOKEN = "<bos>"
EOS_TOKEN = "<eos>"
OOV_TOKEN = "<oov>"
DUR_TOKEN = "<dur>"
SPECIAL_TOKENS: tuple[str, ...] = (PAD_TOKEN, BOS_TOKEN, EOS_TOKEN, OOV_TOKEN, DUR_TOKEN)

# Namespace prefixes for session-metadata vocabulary entries, so they can
# never collide with a command token and can be identified later (e.g. to
# exempt them from re-ID augmentation -- see CommandTokenizer.metadata_ids).
BANNER_PREFIX = "banner:"
CRED_PREFIX = "cred:"


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
        use_metadata: Encode ``ssh_client_banner``/``auth_attempts``/duration as
            extra tokens right after ``<bos>`` (see ``CommandTokenizer.encode``).
            The reason this exists: 97%+ of real MIRAGE sessions have zero
            commands and would otherwise all encode to the identical
            ``[<bos>, <eos>]`` sequence, giving a re-ID model nothing to learn
            from for the overwhelming majority of the corpus. Kept as a toggle
            (mirrors ``SessionEmbedderConfig.use_timing``) for a token-only
            ablation.
        metadata_top_k: Vocabulary budget for banner + credential tokens,
            counted and capped *separately* from ``top_k`` -- the near-ubiquitous
            banner token (``SSH-2.0-Go`` alone is 81.5% of sessions) would
            otherwise crowd out real command tokens if they shared one budget.
        duration_mean: Corpus mean of the log-scaled session duration, for
            optional standardization of the ``<dur>`` token's timing value.
        duration_std: Corpus std of the log-scaled session duration.
        version: Schema version of the serialized artifacts.
    """

    mode: Mode = "command"
    top_k: int = 500
    add_bos: bool = True
    add_eos: bool = True
    timing_log_base: float = math.e
    timing_mean: float = 0.0
    timing_std: float = 1.0
    use_metadata: bool = True
    metadata_top_k: int = 100
    duration_mean: float = 0.0
    duration_std: float = 1.0
    version: int = 2


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
    def dur_id(self) -> int:
        return self._token_to_id[DUR_TOKEN]

    @property
    def vocab_size(self) -> int:
        """Total vocabulary size, including special tokens."""
        return len(self._id_to_token)

    @property
    def metadata_ids(self) -> frozenset[int]:
        """Vocabulary ids of every banner/credential token plus ``<dur>``.

        For a caller (e.g. the re-ID augmenter) that needs to exempt session-
        metadata positions from command-oriented augmentation the same way it
        already exempts ``<pad>``/``<bos>``/``<eos>``.
        """
        ids = {
            i
            for tok, i in self._token_to_id.items()
            if tok.startswith(BANNER_PREFIX) or tok.startswith(CRED_PREFIX)
        }
        ids.add(self.dur_id)
        return frozenset(ids)

    def __len__(self) -> int:
        return self.vocab_size

    # -- Fitting ------------------------------------------------------------

    def fit(self, sessions: Iterable[Session]) -> "CommandTokenizer":
        """Build the vocabulary and timing statistics from a corpus.

        Counts normalized commands across all sessions, keeps the ``top_k`` most
        frequent as the vocabulary, and computes the corpus mean/std of the
        log-ICI for optional timing standardization. When ``config.use_metadata``
        is set, also counts banner/credential tokens into a *separate*
        ``metadata_top_k``-capped vocabulary tier, and fits the log-duration
        mean/std used to standardize the ``<dur>`` token's timing value.

        Args:
            sessions: Iterable of sessions (consumed once).

        Returns:
            ``self``, for chaining.
        """
        counts: Counter[str] = Counter()
        metadata_counts: Counter[str] = Counter()
        log_icis: list[float] = []
        log_durations: list[float] = []

        for session in sessions:
            for raw in session.raw_commands():
                token = self._normalize(raw)
                if token:
                    counts[token] += 1
            for delta in session.inter_command_deltas_ms():
                log_icis.append(self._log_ici(max(delta, 0)))
            if self.config.use_metadata:
                if session.ssh_client_banner:
                    metadata_counts[self._banner_token(session.ssh_client_banner)] += 1
                for attempt in session.auth_attempts:
                    metadata_counts[
                        self._credential_token(attempt.username, attempt.credential)
                    ] += 1
                log_durations.append(self._log_ms(session.effective_duration_ms))

        self._install_specials()
        for token, _ in counts.most_common(self.config.top_k):
            if token not in self._token_to_id:
                self._token_to_id[token] = len(self._id_to_token)
                self._id_to_token.append(token)
        if self.config.use_metadata:
            for token, _ in metadata_counts.most_common(self.config.metadata_top_k):
                if token not in self._token_to_id:
                    self._token_to_id[token] = len(self._id_to_token)
                    self._id_to_token.append(token)

        if log_icis:
            mean = sum(log_icis) / len(log_icis)
            var = sum((x - mean) ** 2 for x in log_icis) / len(log_icis)
            self.config.timing_mean = mean
            self.config.timing_std = math.sqrt(var) or 1.0

        if log_durations:
            mean = sum(log_durations) / len(log_durations)
            var = sum((x - mean) ** 2 for x in log_durations) / len(log_durations)
            self.config.duration_mean = mean
            self.config.duration_std = math.sqrt(var) or 1.0

        return self

    # -- Timing transform ---------------------------------------------------

    def _log_ms(self, value_ms: float) -> float:
        """Log-scale a millisecond-domain quantity: ``log(1 + value_ms)``.

        Zero maps to ``0``; the heavy right tail of ms-scale durations (a
        think-pause, or a whole session's length) is compressed. Shared by the
        inter-command-interval transform and the ``<dur>`` token's duration
        transform -- both are "how many milliseconds did this span," just at
        different scales.
        """
        value = math.log1p(max(value_ms, 0.0))
        base = self.config.timing_log_base
        if base != math.e:
            value /= math.log(base)
        return value

    def _log_ici(self, delta_ms: float) -> float:
        """Log-scale an inter-command interval (the log-ISI transform).

        The neuroscience rationale: ISIs are approximately log-normally
        distributed, so the log domain is where Gaussian-friendly models and
        distance metrics behave.
        """
        return self._log_ms(delta_ms)

    def _maybe_standardize(self, log_ici: float, standardize: bool) -> float:
        if not standardize:
            return log_ici
        return (log_ici - self.config.timing_mean) / (self.config.timing_std or 1.0)

    def _maybe_standardize_duration(self, log_duration: float, standardize: bool) -> float:
        if not standardize:
            return log_duration
        return (log_duration - self.config.duration_mean) / (self.config.duration_std or 1.0)

    # -- Metadata token formatting --------------------------------------------

    @staticmethod
    def _banner_token(banner: str) -> str:
        return f"{BANNER_PREFIX}{banner}"

    @staticmethod
    def _credential_token(username: str, credential: str) -> str:
        return f"{CRED_PREFIX}{username}:{credential}"

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

        if self.config.use_metadata:
            # Metadata block: <dur> (real signal, in the timing channel) then
            # the banner and every credential tried (real signal, in the token
            # channel). None of these participate in the inter-command-interval
            # chain below -- prev_offset is still unset when the loop starts.
            ids.append(self.dur_id)
            log_duration = self._log_ms(session.effective_duration_ms)
            timing.append(self._maybe_standardize_duration(log_duration, standardize_timing))

            if session.ssh_client_banner:
                banner_tok = self._banner_token(session.ssh_client_banner)
                ids.append(self._token_to_id.get(banner_tok, self.oov_id))
                timing.append(self._maybe_standardize(0.0, standardize_timing))

            for attempt in session.auth_attempts:
                cred_tok = self._credential_token(attempt.username, attempt.credential)
                ids.append(self._token_to_id.get(cred_tok, self.oov_id))
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
