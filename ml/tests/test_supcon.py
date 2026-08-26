from __future__ import annotations

import pytest
import torch

from mirage.reid.loss import UNKNOWN_TOOLKIT, CampaignAwareReIDLoss
from mirage.training.objective import SupConLoss


def _embed(*groups: tuple[float, float]) -> torch.Tensor:
    """Build unit-length 2-D embeddings from angle-free (x, y) seed points."""
    z = torch.tensor(groups, dtype=torch.float32)
    return torch.nn.functional.normalize(z, dim=1)


def test_supcon_rejects_nonpositive_temperature() -> None:
    with pytest.raises(ValueError):
        SupConLoss(temperature=0.0)


def test_supcon_rejects_label_length_mismatch() -> None:
    criterion = SupConLoss()
    z = torch.randn(3, 4)
    with pytest.raises(ValueError):
        criterion(z, ["a", "b"])


def test_supcon_prefers_tighter_same_label_clusters() -> None:
    # Two well-separated pairs, same label within each pair. Tightening one
    # pair (without moving the other) must strictly lower that pair's loss
    # contribution -- the basic "pull positives together" property.
    criterion = SupConLoss(temperature=0.5)
    labels = ["a", "a", "b", "b"]

    loose = _embed((1.0, 0.05), (1.0, -0.05), (-1.0, 0.05), (-1.0, -0.05))
    tight = _embed((1.0, 0.005), (1.0, -0.005), (-1.0, 0.05), (-1.0, -0.05))

    assert criterion(tight, labels).item() < criterion(loose, labels).item()


def test_supcon_zero_when_only_one_example_per_label() -> None:
    # No anchor has a same-label positive in the batch -> nothing to optimize.
    criterion = SupConLoss(temperature=0.5)
    z = torch.randn(4, 6)
    loss = criterion(z, ["a", "b", "c", "d"])
    assert loss.item() == pytest.approx(0.0)


def test_supcon_ignore_label_excludes_anchors_but_stays_a_negative() -> None:
    # Three "unknown"-labelled rows should never anchor a loss term among
    # themselves (they're not asserted to share an identity), but a real
    # anchor's loss should still see them as ordinary negatives.
    criterion = SupConLoss(temperature=0.5, ignore_label="unknown")
    labels = ["real", "real", "unknown", "unknown", "unknown"]
    z = torch.randn(5, 8)

    loss_with_unknowns = criterion(z, labels)

    # Compute the same "real"-anchor term by hand: with only two "real" rows,
    # each is the other's sole positive, and everything else (including the
    # three "unknown" rows) is a negative in the denominator.
    zn = torch.nn.functional.normalize(z, dim=1)
    sim = (zn @ zn.t()) / 0.5
    sim.fill_diagonal_(float("-inf"))
    log_prob = sim - torch.logsumexp(sim, dim=1, keepdim=True)
    expected = -0.5 * (log_prob[0, 1] + log_prob[1, 0])

    assert loss_with_unknowns.item() == pytest.approx(expected.item(), rel=1e-4)


def test_supcon_all_ignored_labels_yields_zero() -> None:
    criterion = SupConLoss(temperature=0.5, ignore_label="unknown")
    z = torch.randn(4, 6)
    loss = criterion(z, ["unknown"] * 4)
    assert loss.item() == pytest.approx(0.0)


def test_supcon_gradients_flow_to_a_qualifying_anchor() -> None:
    criterion = SupConLoss(temperature=0.5)
    z = torch.randn(6, 5, requires_grad=True)
    loss = criterion(z, ["a", "a", "b", "b", "c", "d"])
    loss.backward()
    assert z.grad is not None
    assert torch.isfinite(z.grad).all()


# ---------------------------------------------------------------------------
# CampaignAwareReIDLoss
# ---------------------------------------------------------------------------


def test_campaign_aware_loss_rejects_out_of_range_coarse_weight() -> None:
    with pytest.raises(ValueError):
        CampaignAwareReIDLoss(coarse_weight=1.5)
    with pytest.raises(ValueError):
        CampaignAwareReIDLoss(coarse_weight=-0.1)


def test_campaign_aware_loss_equals_weighted_sum_of_its_two_terms() -> None:
    torch.manual_seed(0)
    z = torch.randn(6, 5)
    identity = ["ip1", "ip1", "ip2", "ip2", "ip3", "ip3"]
    toolkit = ["campaign_tier1", "campaign_tier1", UNKNOWN_TOOLKIT, UNKNOWN_TOOLKIT, "campaign_tier2", "campaign_tier2"]

    combo = CampaignAwareReIDLoss(coarse_weight=0.3)
    identity_only = SupConLoss(temperature=combo.identity_criterion.temperature)
    toolkit_only = SupConLoss(
        temperature=combo.toolkit_criterion.temperature, ignore_label=UNKNOWN_TOOLKIT
    )

    expected = identity_only(z, identity) + 0.3 * toolkit_only(z, toolkit)
    assert combo(z, identity, toolkit).item() == pytest.approx(expected.item(), rel=1e-5)


def test_campaign_aware_loss_ignores_unknown_toolkit_majority() -> None:
    # A batch where almost everyone is UNKNOWN_TOOLKIT must not have the
    # toolkit term silently treat "unknown" as one giant shared identity: the
    # coarse term should come only from the two real campaign_tier1 rows.
    torch.manual_seed(1)
    z = torch.randn(10, 5)
    identity = [f"ip{i}" for i in range(10)]
    toolkit = [UNKNOWN_TOOLKIT] * 8 + ["campaign_tier1", "campaign_tier1"]

    combo = CampaignAwareReIDLoss(coarse_weight=1.0)
    toolkit_only = SupConLoss(
        temperature=combo.toolkit_criterion.temperature, ignore_label=UNKNOWN_TOOLKIT
    )
    identity_only = SupConLoss(temperature=combo.identity_criterion.temperature)

    coarse_term = toolkit_only(z, toolkit)
    # With no repeated identity labels the identity term is exactly zero, so
    # the whole combined loss must equal the (non-zero) coarse term alone.
    assert identity_only(z, identity).item() == pytest.approx(0.0)
    assert combo(z, identity, toolkit).item() == pytest.approx(coarse_term.item(), rel=1e-5)
    assert coarse_term.item() != pytest.approx(0.0)
