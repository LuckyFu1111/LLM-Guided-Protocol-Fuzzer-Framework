"""
MeasurementMatrix — centralised metric tracking for fuzz campaigns.

Tracks:
  - Code Coverage: unique paths (line + branch hit counts from GCOV).
  - Vulnerability Metrics: TTFB (time to first bug), weighted CVE recall.
  - Stateful Metrics: state-transition coverage (unique response-sequence hashes).
  - LLM Efficiency: validity rate, path gain, semantic novelty.
  - Real-time Visualization: PNG chart of coverage evolution with LLM trigger annotations.
"""

from __future__ import annotations

import csv
import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CrashRecord:
    timestamp: float
    iteration: int
    signal: int
    crash_input: bytes
    backtrace: str = ""
    matched_cve: str = ""
    cve_weight: int = 0


@dataclass
class LLMBatchResult:
    """Outcome of a single LLM mutation batch."""
    timestamp: float
    iteration: int
    seeds_requested: int
    seeds_returned: int
    valid_seeds: int              # seeds that pass protocol syntax check
    new_paths_discovered: int
    traditional_paths_at_time: int  # baseline comparison


class MeasurementMatrix:
    """Accumulate and persist all experiment metrics."""

    def __init__(
        self,
        output_path: str | Path = "fuzz_lab/metrics/results.csv",
        plot_dir: str | Path = "fuzz_lab/metrics/plots",
        plot_interval_sec: float = 600.0,  # 10 minutes
    ) -> None:
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.plot_dir = Path(plot_dir)
        self.plot_dir.mkdir(parents=True, exist_ok=True)
        self.plot_interval_sec = plot_interval_sec

        self._start_time: float = time.time()
        self._ttfb: Optional[float] = None  # seconds since start

        # Coverage timeline: (iteration, timestamp, unique_paths, line_pct, branch_pct)
        self._coverage_timeline: List[Tuple[int, float, int, float, float]] = []

        # Crashes
        self._crashes: List[CrashRecord] = []
        self._triggered_cves: Dict[str, CrashRecord] = {}

        # State-transition tracking (for stateful protocols)
        self._state_sequence_hashes: Set[str] = set()

        # LLM efficiency
        self._llm_batches: List[LLMBatchResult] = []

        # Semantic novelty scores (cosine similarities)
        self._novelty_scores: List[float] = []

        # Periodic plotting
        self._plot_timer: Optional[threading.Timer] = None
        self._plot_counter: int = 0

    # ------------------------------------------------------------------
    # Code Coverage
    # ------------------------------------------------------------------

    def log_coverage(
        self,
        iteration: int,
        unique_paths: int,
        line_pct: float,
        branch_pct: float,
    ) -> None:
        self._coverage_timeline.append((
            iteration, time.time(), unique_paths, line_pct, branch_pct,
        ))

    def get_latest_coverage(self) -> Optional[Tuple[int, float, int, float, float]]:
        if not self._coverage_timeline:
            return None
        return self._coverage_timeline[-1]

    # ------------------------------------------------------------------
    # Vulnerability Metrics
    # ------------------------------------------------------------------

    def log_crash(
        self,
        iteration: int,
        signal: int,
        crash_input: bytes,
        backtrace: str = "",
        matched_cve: str = "",
        cve_weight: int = 0,
    ) -> CrashRecord:
        now = time.time()
        rec = CrashRecord(
            timestamp=now,
            iteration=iteration,
            signal=signal,
            crash_input=crash_input,
            backtrace=backtrace,
            matched_cve=matched_cve,
            cve_weight=cve_weight,
        )
        self._crashes.append(rec)

        if self._ttfb is None:
            self._ttfb = now - self._start_time
            logger.info("TTFB: %.2f seconds (iteration %d)", self._ttfb, iteration)

        if matched_cve and matched_cve not in self._triggered_cves:
            self._triggered_cves[matched_cve] = rec
            logger.info("CVE %s triggered at iteration %d (weight=%d)",
                        matched_cve, iteration, cve_weight)

        return rec

    @property
    def ttfb(self) -> Optional[float]:
        return self._ttfb

    @property
    def total_crashes(self) -> int:
        return len(self._crashes)

    @property
    def unique_crashes(self) -> int:
        seen: Set[str] = set()
        for c in self._crashes:
            h = hashlib.sha256(c.crash_input).hexdigest()[:16]
            seen.add(h)
        return len(seen)

    def weighted_cve_recall(self) -> float:
        """Sum of weights of all triggered CVEs."""
        return sum(r.cve_weight for r in self._triggered_cves.values())

    def triggered_cve_ids(self) -> List[str]:
        return sorted(self._triggered_cves.keys())

    # ------------------------------------------------------------------
    # Stateful Metrics
    # ------------------------------------------------------------------

    def log_state_transition(self, response_sequence: List[bytes]) -> bool:
        """Hash a sequence of responses and record it.  Returns True if new."""
        h = hashlib.sha256(b"|".join(response_sequence)).hexdigest()[:16]
        is_new = h not in self._state_sequence_hashes
        if is_new:
            self._state_sequence_hashes.add(h)
        return is_new

    @property
    def state_transition_coverage(self) -> int:
        return len(self._state_sequence_hashes)

    # ------------------------------------------------------------------
    # LLM Efficiency
    # ------------------------------------------------------------------

    def log_llm_batch(
        self,
        iteration: int,
        seeds_requested: int,
        seeds_returned: int,
        valid_seeds: int,
        new_paths_discovered: int,
        traditional_paths_at_time: int,
    ) -> None:
        self._llm_batches.append(LLMBatchResult(
            timestamp=time.time(),
            iteration=iteration,
            seeds_requested=seeds_requested,
            seeds_returned=seeds_returned,
            valid_seeds=valid_seeds,
            new_paths_discovered=new_paths_discovered,
            traditional_paths_at_time=traditional_paths_at_time,
        ))

    def llm_validity_rate(self) -> float:
        """% of LLM seeds that passed protocol syntax validation."""
        total_returned = sum(b.seeds_returned for b in self._llm_batches)
        total_valid = sum(b.valid_seeds for b in self._llm_batches)
        if total_returned == 0:
            return 0.0
        return (total_valid / total_returned) * 100.0

    def llm_path_gain(self) -> float:
        """Average new paths per LLM batch vs. traditional mutation."""
        if not self._llm_batches:
            return 0.0
        return sum(b.new_paths_discovered for b in self._llm_batches) / len(self._llm_batches)

    def log_semantic_novelty(self, cosine_similarity: float) -> None:
        """Record a cosine-similarity score between LLM seed and original corpus."""
        self._novelty_scores.append(cosine_similarity)

    def avg_semantic_novelty(self) -> float:
        if not self._novelty_scores:
            return 0.0
        return sum(self._novelty_scores) / len(self._novelty_scores)

    # ------------------------------------------------------------------
    # Real-time Visualization
    # ------------------------------------------------------------------

    def plot_coverage_evolution(self, output_path: str | Path | None = None) -> Path:
        """Generate a PNG chart of coverage over time with LLM trigger annotations.

        X-axis : Iteration (primary) / Elapsed time (secondary).
        Y-axis : Unique path count.
        Vertical red dashed lines mark iterations where the LLM mutator
        was triggered, visualising the "Coverage Jump" effect.
        """
        try:
            import matplotlib
            matplotlib.use("Agg")  # Non-interactive backend for headless PNG output
            import matplotlib.pyplot as plt
            import matplotlib.ticker as ticker
        except ImportError:
            logger.warning(
                "matplotlib not installed — skipping plot. "
                "Install with: pip install matplotlib"
            )
            return self.plot_dir / "coverage_evolution.png"

        if not self._coverage_timeline:
            logger.info("No coverage data to plot yet")
            return self.plot_dir / "coverage_evolution.png"

        # Unpack timeline
        iterations = [r[0] for r in self._coverage_timeline]
        timestamps = [r[1] for r in self._coverage_timeline]
        unique_paths = [r[2] for r in self._coverage_timeline]
        line_pcts = [r[3] for r in self._coverage_timeline]
        branch_pcts = [r[4] for r in self._coverage_timeline]

        # Convert timestamps to elapsed minutes
        t0 = timestamps[0]
        elapsed_min = [(t - t0) / 60.0 for t in timestamps]

        # LLM trigger iterations
        llm_iters = [b.iteration for b in self._llm_batches]

        # Crash iterations
        crash_iters = [c.iteration for c in self._crashes]

        # --- Plot ---
        fig, ax1 = plt.subplots(figsize=(14, 7))

        # Primary: Unique paths
        color_paths = "#2196F3"
        ax1.plot(iterations, unique_paths, color=color_paths, linewidth=1.5,
                 label="Unique Paths (lines+branches hit)", zorder=3)
        ax1.set_xlabel("Iteration", fontsize=12)
        ax1.set_ylabel("Unique Path Count", color=color_paths, fontsize=12)
        ax1.tick_params(axis="y", labelcolor=color_paths)

        # Secondary Y-axis: Line coverage %
        ax2 = ax1.twinx()
        color_pct = "#4CAF50"
        ax2.plot(iterations, line_pcts, color=color_pct, linewidth=1.0,
                 alpha=0.6, linestyle="--", label="Line Coverage %")
        ax2.set_ylabel("Line Coverage %", color=color_pct, fontsize=12)
        ax2.tick_params(axis="y", labelcolor=color_pct)

        # Secondary X-axis: Elapsed time (top)
        ax_top = ax1.twiny()
        ax_top.set_xlim(ax1.get_xlim())
        # Map iteration ticks to elapsed minutes
        if len(iterations) > 1 and len(elapsed_min) > 1:
            ax_top.plot(elapsed_min, unique_paths, alpha=0)  # invisible, just for axis
            ax_top.set_xlabel("Elapsed Time (minutes)", fontsize=10)
            ax_top.xaxis.set_major_formatter(ticker.FormatStrFormatter("%.1f"))

        # LLM trigger vertical lines (red dashed)
        for i, llm_iter in enumerate(llm_iters):
            label = "LLM Triggered" if i == 0 else None
            ax1.axvline(x=llm_iter, color="#F44336", linestyle="--",
                        alpha=0.7, linewidth=1.2, label=label, zorder=2)

        # Crash markers (orange triangles)
        for i, crash_iter in enumerate(crash_iters):
            label = "Crash" if i == 0 else None
            # Find the path count at this iteration (approximate)
            closest_idx = min(range(len(iterations)),
                              key=lambda j: abs(iterations[j] - crash_iter))
            ax1.plot(crash_iter, unique_paths[closest_idx], "v",
                     color="#FF9800", markersize=8, label=label, zorder=4)

        # Legend
        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2,
                   loc="upper left", fontsize=9, framealpha=0.9)

        # Title with summary stats
        title_parts = [
            f"Coverage Evolution — Peak: {max(unique_paths)} paths",
        ]
        if self._ttfb is not None:
            title_parts.append(f"TTFB: {self._ttfb:.1f}s")
        if llm_iters:
            title_parts.append(f"LLM triggers: {len(llm_iters)}")
        ax1.set_title("  |  ".join(title_parts), fontsize=13, pad=25)

        ax1.grid(True, alpha=0.3)
        fig.tight_layout()

        # Save
        self._plot_counter += 1
        if output_path is None:
            output_path = self.plot_dir / f"coverage_evolution_{self._plot_counter:04d}.png"
        else:
            output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        fig.savefig(str(output_path), dpi=150, bbox_inches="tight")
        plt.close(fig)

        logger.info("Coverage plot saved to %s", output_path)
        return output_path

    def start_periodic_plotting(self) -> None:
        """Start a background timer that generates a coverage plot every
        ``plot_interval_sec`` seconds (default: 10 minutes)."""
        self._schedule_next_plot()
        logger.info("Periodic plotting started (every %.0fs)", self.plot_interval_sec)

    def stop_periodic_plotting(self) -> None:
        """Cancel the periodic plotting timer."""
        if self._plot_timer is not None:
            self._plot_timer.cancel()
            self._plot_timer = None

    def _schedule_next_plot(self) -> None:
        self._plot_timer = threading.Timer(
            self.plot_interval_sec, self._periodic_plot_tick,
        )
        self._plot_timer.daemon = True
        self._plot_timer.start()

    def _periodic_plot_tick(self) -> None:
        try:
            self.plot_coverage_evolution()
        except Exception:
            logger.exception("Periodic plot generation failed")
        finally:
            self._schedule_next_plot()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def summary(self) -> Dict:
        return {
            "elapsed_sec": time.time() - self._start_time,
            "ttfb_sec": self._ttfb,
            "total_crashes": self.total_crashes,
            "unique_crashes": self.unique_crashes,
            "weighted_cve_recall": self.weighted_cve_recall(),
            "triggered_cves": self.triggered_cve_ids(),
            "state_transition_coverage": self.state_transition_coverage,
            "llm_validity_rate_pct": self.llm_validity_rate(),
            "llm_avg_path_gain": self.llm_path_gain(),
            "avg_semantic_novelty": self.avg_semantic_novelty(),
            "coverage_snapshots": len(self._coverage_timeline),
            "llm_batches": len(self._llm_batches),
        }

    def export_csv(self, path: Optional[str | Path] = None) -> Path:
        """Write the coverage timeline to CSV for later analysis with pandas."""
        out = Path(path) if path else self.output_path
        out.parent.mkdir(parents=True, exist_ok=True)

        with open(out, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "iteration", "timestamp", "unique_paths",
                "line_coverage_pct", "branch_coverage_pct",
            ])
            for row in self._coverage_timeline:
                writer.writerow(row)

        logger.info("Coverage timeline exported to %s (%d rows)",
                    out, len(self._coverage_timeline))
        return out
