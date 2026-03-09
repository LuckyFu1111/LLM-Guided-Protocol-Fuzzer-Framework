"""
MeasurementMatrix — centralised metric tracking for fuzz campaigns.

Tracks:
  - Code Coverage: unique paths (line + branch hit counts from GCOV).
  - Vulnerability Metrics: TTFB (time to first bug), weighted CVE recall.
  - Stateful Metrics: state-transition coverage (unique response-sequence hashes).
  - LLM Efficiency: validity rate, path gain, semantic novelty.
"""

from __future__ import annotations

import csv
import hashlib
import logging
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

    def __init__(self, output_path: str | Path = "fuzz_lab/metrics/results.csv") -> None:
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

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
