"""Phase-2 visualization: embedding-space maps, trajectories, cluster quality.

The figures here are the empirical test of the Phase-2 hypothesis:

    Sessions from the same attack tool cluster together in embedding space, AND
    their trajectories have similar shapes even if individual commands differ.

* :func:`~mirage.viz.visualize.plot_embedding_umap` -- 2-D map of the 128-d
  vectors, colored by inferred tool signature (clusters == hypothesis part 1).
* :func:`~mirage.viz.visualize.plot_session_trajectories` -- paths of
  representative sessions through embedding space (shape similarity ==
  hypothesis part 2), with intent-shift moments and convergence points marked.
* :func:`~mirage.viz.visualize.clustering_quality` -- silhouette score as a
  scalar summary of cluster separation.
"""

from __future__ import annotations

from .tool_signature import infer_tool_signature

__all__ = ["infer_tool_signature"]
