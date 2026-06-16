"""Phase-2 neural models for MIRAGE.

Two objects, mirroring the two halves of population-level neural data analysis:

* :class:`~mirage.models.embedding.SessionEmbedder` -- maps a dual-channel
  session (command tokens + log-ICI timing) to a 128-d behavioral embedding,
  and *also* returns the full sequence of hidden states. This is the analogue
  of estimating a low-dimensional neural state from population spiking.

* :class:`~mirage.models.trajectory.TemporalTrajectoryAnalyzer` -- treats the
  sequence of hidden states as a trajectory through embedding space and
  extracts its geometry (velocity, curvature, convergence). This is the direct
  analogue of neural population trajectory analysis in motor cortex.

Both modules depend only on :mod:`torch` (plus stdlib), so they import cleanly
without the Phase-1 data stack.
"""

from __future__ import annotations

from .embedding import (
    SessionEmbedder,
    SessionEmbedderConfig,
    SessionEmbedderOutput,
    SinusoidalPositionalEncoding,
)
from .trajectory import (
    TemporalTrajectoryAnalyzer,
    TrajectoryConfig,
    TrajectoryFeatures,
)

__all__ = [
    "SessionEmbedder",
    "SessionEmbedderConfig",
    "SessionEmbedderOutput",
    "SinusoidalPositionalEncoding",
    "TemporalTrajectoryAnalyzer",
    "TrajectoryConfig",
    "TrajectoryFeatures",
]
