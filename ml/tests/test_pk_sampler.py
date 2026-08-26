from __future__ import annotations

import pytest

from mirage.reid.pk_sampler import PKBatchSampler


def _labels() -> list[str]:
    # 3 identities with plenty of sessions, 1 identity with exactly one.
    return ["a"] * 5 + ["b"] * 5 + ["c"] * 5 + ["solo"]


def test_rejects_p_below_two() -> None:
    with pytest.raises(ValueError):
        PKBatchSampler(_labels(), p=1, k=2)


def test_rejects_k_below_one() -> None:
    with pytest.raises(ValueError):
        PKBatchSampler(_labels(), p=2, k=0)


def test_rejects_p_larger_than_available_identities() -> None:
    with pytest.raises(ValueError):
        PKBatchSampler(_labels(), p=10, k=2)


def test_every_batch_has_exactly_p_times_k_indices() -> None:
    sampler = PKBatchSampler(_labels(), p=3, k=4, batches_per_epoch=20, seed=0)
    for batch in sampler:
        assert len(batch) == 12
    assert len(list(sampler)) == 20


def test_every_batch_has_p_distinct_identities_each_appearing_k_times() -> None:
    labels = _labels()
    sampler = PKBatchSampler(labels, p=3, k=4, batches_per_epoch=10, seed=1)
    for batch in sampler:
        batch_labels = [labels[i] for i in batch]
        counted = {lab: batch_labels.count(lab) for lab in set(batch_labels)}
        assert len(counted) == 3
        assert all(count == 4 for count in counted.values())


def test_singleton_identity_pads_by_repeating_its_one_index() -> None:
    labels = _labels()
    solo_idx = labels.index("solo")
    # Force "solo" to be selected by making it one of only two identities.
    sampler = PKBatchSampler(["solo", "solo_group_filler"] + ["a"], p=2, k=3, batches_per_epoch=5, seed=2)
    for batch in sampler:
        this_labels = (["solo", "solo_group_filler"] + ["a"])
        batch_labels = [this_labels[i] for i in batch]
        # "solo" (index 0) must appear k=3 times even though it has only 1 row.
        if "solo" in batch_labels:
            assert batch_labels.count("solo") == 3
            assert batch.count(0) == 3


def test_indices_stay_within_k_available_when_no_padding_needed() -> None:
    labels = ["a"] * 2 + ["b"] * 2
    sampler = PKBatchSampler(labels, p=2, k=2, batches_per_epoch=5, seed=3)
    for batch in sampler:
        assert sorted(batch) == [0, 1, 2, 3]


def test_reproducible_with_seed() -> None:
    labels = _labels()
    a = list(PKBatchSampler(labels, p=3, k=2, batches_per_epoch=5, seed=42))
    b = list(PKBatchSampler(labels, p=3, k=2, batches_per_epoch=5, seed=42))
    assert a == b
