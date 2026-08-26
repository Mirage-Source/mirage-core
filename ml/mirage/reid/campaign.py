from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Mapping

__all__ = [
    "CampaignMembership",
    "CampaignResult",
    "divisibility_candidates",
    "credential_sets_match",
    "detect_campaign",
]

#: Length of the credential wordlist identified in the MIRAGE preprint,
#: Section VI-A -- the campaign's structural signature is an exact integer
#: multiple of this many sessions per source address.
WORDLIST_LEN: int = 761


@dataclass(frozen=True)
class CampaignMembership:
    """One confirmed campaign member.

    Attributes:
        ip: Source address.
        tier: How many times this address replayed the wordlist
            (``session_count // wordlist_len``).
        session_count: Raw session count for this address.
    """

    ip: str
    tier: int
    session_count: int


@dataclass
class CampaignResult:
    """Output of :func:`detect_campaign`.

    Attributes:
        members: Confirmed campaign addresses (passed both the divisibility
            test and the credential-set-identity check).
        excluded: Addresses whose session count was divisible by the wordlist
            length but whose credential-pair set did *not* match the
            campaign's -- a coincidental divisor, not a real member. Reported
            rather than silently dropped so a caller can see the test has
            specificity (mirrors the paper's negative control, Section VI-B).
    """

    members: list[CampaignMembership] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)

    @property
    def ips(self) -> list[str]:
        return [m.ip for m in self.members]

    @property
    def total_sessions(self) -> int:
        return sum(m.session_count for m in self.members)

    def tier_summary(self) -> dict[int, tuple[int, int]]:
        """``{tier: (n_ips, n_sessions)}``, matching the preprint's Table II."""
        out: dict[int, tuple[int, int]] = {}
        by_tier: dict[int, list[CampaignMembership]] = {}
        for m in self.members:
            by_tier.setdefault(m.tier, []).append(m)
        for tier, members in by_tier.items():
            out[tier] = (len(members), sum(m.session_count for m in members))
        return out


def divisibility_candidates(
    session_counts: Mapping[str, int], wordlist_len: int = WORDLIST_LEN
) -> dict[str, int]:
    """Addresses whose session count is a positive exact multiple of ``wordlist_len``.

    This is the paper's primary test (Section VI-A): testing for divisibility
    rather than equality is what surfaces the tiered campaign structure that an
    equality test (e.g. "count == 761") would miss.

    Args:
        session_counts: ``{ip: session_count}``.
        wordlist_len: The credential-list length to test divisibility against.

    Returns:
        ``{ip: tier}`` where ``tier = session_count // wordlist_len``, for
        every address with a positive count divisible by ``wordlist_len``.

    Raises:
        ValueError: If ``wordlist_len`` is not positive.
    """
    if wordlist_len <= 0:
        raise ValueError("wordlist_len must be positive")
    return {
        ip: n // wordlist_len
        for ip, n in session_counts.items()
        if n > 0 and n % wordlist_len == 0
    }


def credential_sets_match(pair_sets: Mapping[str, frozenset]) -> bool:
    """True iff every address's credential-pair set is identical.

    Args:
        pair_sets: ``{ip: frozenset of (username, credential) pairs}``.

    Returns:
        ``True`` if ``pair_sets`` is empty or every value is equal to every
        other value; ``False`` on any mismatch.
    """
    values = list(pair_sets.values())
    if not values:
        return True
    first = values[0]
    return all(v == first for v in values)


def detect_campaign(
    session_counts: Mapping[str, int],
    credential_pair_sets: Mapping[str, frozenset],
    wordlist_len: int = WORDLIST_LEN,
) -> CampaignResult:
    """Run the full two-stage structural-signature test (paper Section VI-A).

    Stage 1 (:func:`divisibility_candidates`) finds addresses whose session
    count is an exact multiple of the wordlist length -- a necessary but not
    sufficient condition, since an unrelated address could hit a multiple by
    coincidence. Stage 2 confirms each candidate's credential-pair set is
    identical to the campaign's (the *mode* of all candidates' sets, so one
    corrupted or coincidental candidate can't skew the reference); a candidate
    whose set doesn't match is reported as excluded rather than silently
    dropped, so the test's specificity is visible (this is what Section VI-B's
    negative control demonstrates on a different, larger cluster).

    Args:
        session_counts: ``{ip: session_count}`` for every source address.
        credential_pair_sets: ``{ip: frozenset of (username, credential) pairs}``
            for (at least) every divisibility candidate.
        wordlist_len: The credential-list length; defaults to the preprint's
            confirmed value of 761.

    Returns:
        A :class:`CampaignResult` with confirmed members and any addresses
        excluded by the credential-set check.
    """
    candidates = divisibility_candidates(session_counts, wordlist_len)
    if not candidates:
        return CampaignResult()

    candidate_sets = {
        ip: credential_pair_sets[ip] for ip in candidates if ip in credential_pair_sets
    }
    if not candidate_sets:
        return CampaignResult(excluded=sorted(candidates))

    # The reference is the most common credential-pair set among candidates,
    # not simply "the first one" -- robust to a single coincidental divisor
    # (Section VI-A's own reasoning: two independent operators sharing a
    # wordlist is plausible; two independent operators AND arriving at the
    # same execution model AND coincidentally hitting a wordlist-length
    # multiple is not).
    counts = Counter(candidate_sets.values())
    reference = counts.most_common(1)[0][0]

    members: list[CampaignMembership] = []
    excluded: list[str] = []
    for ip, tier in candidates.items():
        pairs = candidate_sets.get(ip)
        if pairs == reference:
            members.append(
                CampaignMembership(ip=ip, tier=tier, session_count=session_counts[ip])
            )
        else:
            excluded.append(ip)
    return CampaignResult(members=members, excluded=excluded)
