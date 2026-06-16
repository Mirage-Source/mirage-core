"""Temporal trajectory analysis of session embeddings.

This module is the direct analogue of **neural population trajectory analysis**
in motor cortex. When a monkey reaches, the population firing vector traces a
smooth, curved path through a low-dimensional neural state space: the path's
*velocity* tracks how fast the movement plan is evolving, its *curvature* marks
moments where the plan changes direction (a corrective sub-movement, a change of
target), and the path settles toward a *fixed point* / attractor as the reach
completes (Churchland, Shenoy, Vyas, and the dynamical-systems view of motor
cortex). We apply exactly that lens to attacker sessions.

The session trajectory
----------------------
A :class:`~mirage.models.embedding.SessionEmbedder` returns a sequence of hidden
states. We define the **trajectory as commands accumulate** to be the running
mean of those hidden states -- i.e. the prefix embedding after each command:

    P_t = mean( h_1 , ... , h_t )

so ``P_t`` is exactly the static session vector the model *would* assign to the
first ``t`` commands. As ``t`` grows, ``P_t`` traces the session's path through
the same 128-d space the clustering lives in. This makes the trajectory and the
static embedding two views of one object: where the session *ends up* vs. *how it
got there*. (Set ``mode="raw"`` to instead analyze the per-position contextual
states directly; the running-mean ``mode="prefix"`` is the default because it is
monotone in evidence and far less jittery, like a trial-averaged neural path.)

What we extract (per session)
-----------------------------
* **velocity / speed** -- ``v_t = P_{t+1} - P_t``; ``speed_t = ||v_t||``. The pace
  of behavioral exploration. A tight ``wget|chmod|exec`` tool covers little ground
  quickly and then stops; a human exploring the filesystem keeps moving.
* **curvature** -- the turning angle between consecutive velocity vectors,
  normalized by step length (a discrete Frenet curvature). Curvature *peaks* are
  **intent-shift moments**: the session pivots in embedding space (recon ->
  privilege escalation -> exfiltration). These are the behavioral analogue of
  corrective sub-movements in a reach.
* **convergence** -- the terminal point ``P_T`` (the attractor the session
  settles into) plus a *settling time*: the first step after which the trajectory
  stays within ``epsilon`` of its endpoint. Tools converge fast and sit still;
  humans converge late or not at all.
* **shape signature** -- a translation/scale-normalized, fixed-length resampling
  of the path. This is the key object for the Phase-2 hypothesis: *sessions from
  the same tool should have similarly shaped trajectories even when the individual
  commands differ.* Comparing shape signatures (not raw commands) tests that
  directly, the way one compares reach trajectories across trials.

Everything here is pure geometry on tensors -- no learnable parameters -- so it
runs under ``torch.no_grad`` at analysis time and is fully differentiable if you
ever want to regularize trajectory shape during training.
"""

from __future__ import annotations

from dataclasses import dataclass

import torch

__all__ = ["TrajectoryConfig", "TrajectoryFeatures", "TemporalTrajectoryAnalyzer"]


@dataclass
class TrajectoryConfig:
    """Configuration for :class:`TemporalTrajectoryAnalyzer`.

    Attributes:
        mode: ``"prefix"`` (running mean of hidden states -- the prefix embedding
            path, default) or ``"raw"`` (per-position contextual states).
        convergence_eps: Settling-time radius, as a *fraction* of the trajectory's
            total path length. The settling step is the first ``t`` after which
            every later point stays within this radius of the endpoint.
        curvature_eps: Numerical floor on segment lengths when normalizing, to
            keep curvature finite where the path momentarily stalls.
        resample_points: Number of points in the normalized shape signature.
        smooth_window: Odd window size for optional moving-average smoothing of
            the trajectory before geometry (1 disables). Smoothing is the analogue
            of trial-averaging / mild temporal filtering of neural trajectories.
        peak_quantile: Curvature quantile above which a step is flagged as an
            intent-shift moment.
    """

    mode: str = "prefix"
    convergence_eps: float = 0.05
    curvature_eps: float = 1e-8
    resample_points: int = 32
    smooth_window: int = 1
    peak_quantile: float = 0.9


@dataclass
class TrajectoryFeatures:
    """Geometric summary of one session's embedding-space trajectory.

    All tensors live on the same device/dtype as the input hidden states.

    Attributes:
        trajectory: ``[T, D]`` the analyzed path (prefix means or raw states).
        velocity: ``[T-1, D]`` discrete velocity vectors ``P_{t+1} - P_t``.
        speed: ``[T-1]`` per-step speed ``||v_t||`` (pace of exploration).
        curvature: ``[T-2]`` discrete curvature (turning) at each interior point.
        intent_shift_indices: Long tensor of trajectory indices whose curvature
            exceeds the configured quantile -- candidate intent-shift moments.
        convergence_point: ``[D]`` the terminal trajectory point ``P_T``.
        convergence_step: Settling time -- first index after which the path stays
            within ``convergence_eps * path_length`` of the endpoint. Equals
            ``T-1`` if the session never settles.
        path_length: Total arc length travelled (sum of speeds).
        net_displacement: Straight-line distance from start to end.
        straightness: ``net_displacement / path_length`` in ``[0, 1]``; 1 == a
            straight dash (a focused tool), small == a meandering exploration.
        mean_speed: Average pace across the session.
        total_curvature: Sum of curvature -- overall "how much the intent turned".
        shape_signature: ``[resample_points, D]`` translation/scale-normalized
            resampling of the path, for cross-session shape comparison.
    """

    trajectory: torch.Tensor
    velocity: torch.Tensor
    speed: torch.Tensor
    curvature: torch.Tensor
    intent_shift_indices: torch.Tensor
    convergence_point: torch.Tensor
    convergence_step: int
    path_length: float
    net_displacement: float
    straightness: float
    mean_speed: float
    total_curvature: float
    shape_signature: torch.Tensor


class TemporalTrajectoryAnalyzer:
    """Extract trajectory geometry from a session's hidden states.

    Stateless and parameter-free: construct once with a :class:`TrajectoryConfig`
    and call :meth:`analyze` per session or :meth:`analyze_batch` over a padded
    batch. See the module docstring for the motor-cortex framing.

    Args:
        config: Geometry/normalization settings; defaults are sensible for 128-d
            embeddings of typical (5-50 command) sessions.
    """

    def __init__(self, config: TrajectoryConfig | None = None) -> None:
        self.config = config or TrajectoryConfig()
        if self.config.mode not in ("prefix", "raw"):
            raise ValueError(f"mode must be 'prefix' or 'raw'; got {self.config.mode!r}")
        if self.config.smooth_window < 1 or self.config.smooth_window % 2 == 0:
            raise ValueError("smooth_window must be a positive odd integer")

    # -- Trajectory construction -------------------------------------------

    def _build_trajectory(self, hidden_states: torch.Tensor) -> torch.Tensor:
        """Construct the path from valid (already-unpadded) hidden states.

        Args:
            hidden_states: ``[T, D]`` of *valid* positions only.

        Returns:
            ``[T, D]`` trajectory according to ``config.mode``.
        """
        if self.config.mode == "prefix":
            # Running mean: P_t = cumsum(h)[t] / (t + 1). This is the prefix
            # embedding -- the static vector for the first t+1 commands.
            cumsum = torch.cumsum(hidden_states, dim=0)
            counts = torch.arange(
                1, hidden_states.size(0) + 1, device=hidden_states.device
            ).unsqueeze(-1).to(hidden_states.dtype)
            traj = cumsum / counts
        else:
            traj = hidden_states
        return self._smooth(traj)

    def _smooth(self, traj: torch.Tensor) -> torch.Tensor:
        """Optional centered moving-average smoothing along time."""
        window = self.config.smooth_window
        if window == 1 or traj.size(0) < window:
            return traj
        # Depthwise 1-D average filter via grouped conv, reflect-padded.
        d = traj.size(1)
        kernel = torch.full((d, 1, window), 1.0 / window, dtype=traj.dtype, device=traj.device)
        x = traj.transpose(0, 1).unsqueeze(0)  # [1, D, T]
        pad = window // 2
        x = torch.nn.functional.pad(x, (pad, pad), mode="reflect")
        x = torch.nn.functional.conv1d(x, kernel, groups=d)
        return x.squeeze(0).transpose(0, 1)

    # -- Geometry -----------------------------------------------------------

    def analyze(self, hidden_states: torch.Tensor) -> TrajectoryFeatures:
        """Analyze one session's hidden-state sequence.

        Args:
            hidden_states: ``[T, D]`` sequence of *valid* hidden states (padding
                already removed). Use :meth:`analyze_batch` to handle padded
                batches.

        Returns:
            A :class:`TrajectoryFeatures`. Degenerate sessions (``T < 3``) return
            zero-filled velocity/curvature with the available scalars, so callers
            never special-case short sessions.
        """
        if hidden_states.dim() != 2:
            raise ValueError(
                f"hidden_states must be [T, D]; got {tuple(hidden_states.shape)}"
            )
        traj = self._build_trajectory(hidden_states)
        T, D = traj.shape
        cfg = self.config

        convergence_point = traj[-1].clone()

        if T < 2:
            zero_v = traj.new_zeros((0, D))
            return TrajectoryFeatures(
                trajectory=traj,
                velocity=zero_v,
                speed=traj.new_zeros((0,)),
                curvature=traj.new_zeros((0,)),
                intent_shift_indices=torch.empty(0, dtype=torch.long, device=traj.device),
                convergence_point=convergence_point,
                convergence_step=max(T - 1, 0),
                path_length=0.0,
                net_displacement=0.0,
                straightness=1.0,
                mean_speed=0.0,
                total_curvature=0.0,
                shape_signature=self._shape_signature(traj),
            )

        # Velocity and speed (pace of exploration).
        velocity = traj[1:] - traj[:-1]  # [T-1, D]
        speed = torch.linalg.vector_norm(velocity, dim=1)  # [T-1]
        path_length = float(speed.sum().item())
        net_disp_vec = traj[-1] - traj[0]
        net_displacement = float(torch.linalg.vector_norm(net_disp_vec).item())
        mean_speed = float(speed.mean().item())
        straightness = net_displacement / path_length if path_length > cfg.curvature_eps else 1.0

        curvature = self._discrete_curvature(velocity, speed)
        total_curvature = float(curvature.sum().item()) if curvature.numel() else 0.0
        intent_shift = self._intent_shift_indices(curvature)
        convergence_step = self._settling_time(traj, path_length)

        return TrajectoryFeatures(
            trajectory=traj,
            velocity=velocity,
            speed=speed,
            curvature=curvature,
            intent_shift_indices=intent_shift,
            convergence_point=convergence_point,
            convergence_step=convergence_step,
            path_length=path_length,
            net_displacement=net_displacement,
            straightness=straightness,
            mean_speed=mean_speed,
            total_curvature=total_curvature,
            shape_signature=self._shape_signature(traj),
        )

    def _discrete_curvature(
        self, velocity: torch.Tensor, speed: torch.Tensor
    ) -> torch.Tensor:
        """Turning angle between consecutive velocity vectors, length-normalized.

        For interior point ``t`` we take the angle ``theta_t`` between ``v_{t-1}``
        and ``v_t`` and divide by the mean adjacent segment length, giving a
        discrete curvature ``kappa_t = theta_t / l_t`` (radians per unit length).
        This is the behavioral analogue of how sharply a neural reach trajectory
        bends -- large where the session changes direction in embedding space.

        Returns:
            ``[T-2]`` curvature tensor (empty if fewer than 2 velocity vectors).
        """
        eps = self.config.curvature_eps
        if velocity.size(0) < 2:
            return velocity.new_zeros((0,))
        v_prev = velocity[:-1]
        v_next = velocity[1:]
        # Turning angle via the half-chord of the *unit* velocity vectors:
        #   theta = 2 * asin( ||a_hat - b_hat|| / 2 ).
        # This is well-conditioned near 0 and pi (unlike acos of a cosine, which
        # has a vertical tangent at +-1 and leaks float32 noise into a straight
        # path), so a collinear trajectory yields curvature exactly 0.
        a = v_prev / torch.linalg.vector_norm(v_prev, dim=1, keepdim=True).clamp(min=eps)
        b = v_next / torch.linalg.vector_norm(v_next, dim=1, keepdim=True).clamp(min=eps)
        half_chord = (0.5 * torch.linalg.vector_norm(a - b, dim=1)).clamp(0.0, 1.0)
        theta = 2.0 * torch.asin(half_chord)  # [T-2], radians in [0, pi]
        seg_len = (0.5 * (speed[:-1] + speed[1:])).clamp(min=eps)
        return theta / seg_len

    def _intent_shift_indices(self, curvature: torch.Tensor) -> torch.Tensor:
        """Flag curvature peaks as intent-shift moments.

        A step is flagged if its curvature exceeds the configured quantile of the
        session's own curvature distribution (self-relative, so it adapts to how
        active the session is). Returned indices are into ``trajectory`` (offset
        by 1, since curvature is defined at interior points).
        """
        if curvature.numel() == 0:
            return torch.empty(0, dtype=torch.long, device=curvature.device)
        threshold = torch.quantile(curvature, self.config.peak_quantile)
        # +1 maps a curvature index k (between v_k and v_{k+1}) to trajectory point k+1.
        peaks = torch.nonzero(curvature >= threshold, as_tuple=False).squeeze(-1) + 1
        return peaks.to(torch.long)

    def _settling_time(self, traj: torch.Tensor, path_length: float) -> int:
        """First step after which the path stays near its endpoint (convergence).

        Mirrors the "settling time" of a dynamical system relaxing to a fixed
        point. We sweep from the end backward and find the earliest index from
        which *all* subsequent points lie within ``eps * path_length`` of the
        terminal point.
        """
        if traj.size(0) < 2 or path_length <= self.config.curvature_eps:
            return traj.size(0) - 1
        radius = self.config.convergence_eps * path_length
        dist_to_end = torch.linalg.vector_norm(traj - traj[-1], dim=1)  # [T]
        outside = dist_to_end > radius  # bool [T]
        if not bool(outside.any()):
            return 0
        # Last index that is still outside the radius; settling begins after it.
        last_outside = int(torch.nonzero(outside, as_tuple=False).max().item())
        return min(last_outside + 1, traj.size(0) - 1)

    def _shape_signature(self, traj: torch.Tensor) -> torch.Tensor:
        """Translation/scale-normalized, fixed-length resampling of the path.

        Removes *where* and *how big* the trajectory is, keeping only its *shape*,
        so two same-tool sessions with different commands but similar geometry map
        to nearby signatures. Steps:

        1. Center on the trajectory mean (remove translation).
        2. Arc-length resample to ``resample_points`` (remove speed profile).
        3. Scale to unit Frobenius norm (remove overall size).

        Returns:
            ``[resample_points, D]`` shape descriptor.
        """
        k = self.config.resample_points
        D = traj.size(1)
        if traj.size(0) == 1:
            return traj.new_zeros((k, D))

        centered = traj - traj.mean(dim=0, keepdim=True)
        # Cumulative arc length, normalized to [0, 1].
        seg = torch.linalg.vector_norm(centered[1:] - centered[:-1], dim=1)
        arc = torch.cat([seg.new_zeros(1), torch.cumsum(seg, dim=0)])
        total = arc[-1]
        if float(total.item()) <= self.config.curvature_eps:
            return traj.new_zeros((k, D))
        arc = arc / total
        targets = torch.linspace(0.0, 1.0, k, device=traj.device, dtype=traj.dtype)
        resampled = self._interp_path(arc, centered, targets)
        norm = torch.linalg.matrix_norm(resampled).clamp(min=self.config.curvature_eps)
        return resampled / norm

    @staticmethod
    def _interp_path(
        arc: torch.Tensor, points: torch.Tensor, targets: torch.Tensor
    ) -> torch.Tensor:
        """Piecewise-linear interpolation of ``points`` at normalized arc-length
        positions ``targets``.

        Args:
            arc: ``[T]`` monotone non-decreasing arc-length positions in ``[0, 1]``.
            points: ``[T, D]`` trajectory points at those positions.
            targets: ``[K]`` query positions in ``[0, 1]``.

        Returns:
            ``[K, D]`` interpolated points.
        """
        # For each target, find the right bracket index in arc.
        idx = torch.searchsorted(arc, targets.clamp(0.0, 1.0), right=True)
        idx = idx.clamp(1, arc.size(0) - 1)
        lo = idx - 1
        arc_lo = arc[lo]
        arc_hi = arc[idx]
        denom = (arc_hi - arc_lo).clamp(min=1e-12)
        w = ((targets - arc_lo) / denom).unsqueeze(-1)  # [K, 1]
        return points[lo] * (1.0 - w) + points[idx] * w

    # -- Batch helper -------------------------------------------------------

    def analyze_batch(
        self,
        hidden_states: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> list[TrajectoryFeatures]:
        """Analyze a padded batch by slicing each row to its valid length.

        Args:
            hidden_states: ``[B, L, D]`` (e.g. ``SessionEmbedderOutput.hidden_states``).
            attention_mask: ``[B, L]`` with ``1`` for valid positions.

        Returns:
            A list of ``B`` :class:`TrajectoryFeatures`, one per session.
        """
        lengths = attention_mask.sum(dim=1).to(torch.long)
        out: list[TrajectoryFeatures] = []
        for i in range(hidden_states.size(0)):
            valid = int(lengths[i].item())
            out.append(self.analyze(hidden_states[i, :valid]))
        return out
