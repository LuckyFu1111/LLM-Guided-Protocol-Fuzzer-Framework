"""
CoverageMonitor — GCOV/LCOV integration for coverage-guided fuzzing.

Responsibilities:
  1. Trigger gcov data flush inside the Docker container.
  2. Run lcov to collect coverage into a .info tracefile.
  3. Parse the tracefile to extract total lines, lines hit, branches hit,
     and unique-path counts.
  4. Detect stagnation (no new coverage in a sliding window of iterations).

The parser handles the standard LCOV tracefile format:
  TN:   — test name
  SF:   — source file
  DA:   — line data  (DA:<line_number>,<execution_count>)
  LF:   — lines found (total instrumentable lines in that source file)
  LH:   — lines hit   (lines executed at least once)
  BRDA: — branch data (BRDA:<line>,<block>,<branch>,<taken>)
  BRF:  — branches found
  BRH:  — branches hit
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class FileCoverage:
    """Coverage data for a single source file inside the target."""
    source_file: str
    lines_found: int = 0           # LF — total instrumentable lines
    lines_hit: int = 0             # LH — lines executed >= 1
    branches_found: int = 0        # BRF
    branches_hit: int = 0          # BRH
    line_details: Dict[int, int] = field(default_factory=dict)      # line_no -> exec_count
    branch_details: List[Tuple[int, int, int, int]] = field(        # (line, block, branch, taken)
        default_factory=list,
    )


@dataclass
class CoverageSnapshot:
    """Aggregate coverage across all source files at a point in time."""
    timestamp: float
    iteration: int
    total_lines: int = 0
    total_lines_hit: int = 0
    total_branches: int = 0
    total_branches_hit: int = 0
    file_coverages: Dict[str, FileCoverage] = field(default_factory=dict)

    @property
    def line_coverage_pct(self) -> float:
        if self.total_lines == 0:
            return 0.0
        return (self.total_lines_hit / self.total_lines) * 100.0

    @property
    def branch_coverage_pct(self) -> float:
        if self.total_branches == 0:
            return 0.0
        return (self.total_branches_hit / self.total_branches) * 100.0

    @property
    def unique_paths(self) -> int:
        """Unique paths ≈ total distinct lines hit + distinct branches hit."""
        return self.total_lines_hit + self.total_branches_hit

    def coverage_hash(self) -> str:
        """Deterministic hash of which lines/branches are hit.

        Used for deduplication and state-transition tracking.
        """
        parts: list[str] = []
        for sf in sorted(self.file_coverages):
            fc = self.file_coverages[sf]
            hit_lines = sorted(l for l, c in fc.line_details.items() if c > 0)
            hit_branches = sorted(
                (b[0], b[1], b[2]) for b in fc.branch_details if b[3] > 0
            )
            parts.append(f"{sf}:L{hit_lines}:B{hit_branches}")
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# LCOV Tracefile Parser
# ---------------------------------------------------------------------------

class LcovParser:
    """Parse an LCOV .info tracefile into a CoverageSnapshot."""

    # Precompiled regexes for hot-path parsing
    _RE_DA = re.compile(r"^DA:(\d+),(\d+)")
    _RE_BRDA = re.compile(r"^BRDA:(\d+),(\d+),(\d+),(-|\d+)")

    @classmethod
    def parse_file(cls, info_path: str | Path, iteration: int = 0) -> CoverageSnapshot:
        """Read an lcov .info file from disk and return a CoverageSnapshot."""
        info_path = Path(info_path)
        if not info_path.exists():
            raise FileNotFoundError(f"LCOV tracefile not found: {info_path}")

        with open(info_path, "r", encoding="utf-8", errors="replace") as fh:
            return cls.parse_lines(fh.readlines(), iteration=iteration)

    @classmethod
    def parse_lines(cls, lines: List[str], iteration: int = 0) -> CoverageSnapshot:
        snap = CoverageSnapshot(
            timestamp=time.time(),
            iteration=iteration,
        )

        current_fc: Optional[FileCoverage] = None

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("TN:"):
                continue

            # -- Source file boundary -----------------------------------------
            if line.startswith("SF:"):
                source_file = line[3:]
                current_fc = FileCoverage(source_file=source_file)
                snap.file_coverages[source_file] = current_fc
                continue

            if current_fc is None:
                continue

            # -- Line data ----------------------------------------------------
            m = cls._RE_DA.match(line)
            if m:
                line_no = int(m.group(1))
                exec_count = int(m.group(2))
                current_fc.line_details[line_no] = exec_count
                continue

            # -- Branch data --------------------------------------------------
            m = cls._RE_BRDA.match(line)
            if m:
                taken_str = m.group(4)
                taken = 0 if taken_str == "-" else int(taken_str)
                current_fc.branch_details.append((
                    int(m.group(1)),   # line
                    int(m.group(2)),   # block
                    int(m.group(3)),   # branch
                    taken,
                ))
                continue

            # -- Summary counters (per source file) ---------------------------
            if line.startswith("LF:"):
                current_fc.lines_found = int(line[3:])
            elif line.startswith("LH:"):
                current_fc.lines_hit = int(line[3:])
            elif line.startswith("BRF:"):
                current_fc.branches_found = int(line[4:])
            elif line.startswith("BRH:"):
                current_fc.branches_hit = int(line[4:])
            elif line == "end_of_record":
                # Finalize this file — accumulate into snapshot totals.
                snap.total_lines += current_fc.lines_found
                snap.total_lines_hit += current_fc.lines_hit
                snap.total_branches += current_fc.branches_found
                snap.total_branches_hit += current_fc.branches_hit
                current_fc = None

        return snap


# ---------------------------------------------------------------------------
# CoverageMonitor — live interaction with a running Docker container
# ---------------------------------------------------------------------------

class CoverageMonitor:
    """Manages coverage data collection from an instrumented Docker target.

    Parameters
    ----------
    container_id : str
        Docker container ID or name.
    gcov_prefix : str
        Absolute path inside the container where .gcda files land.
    local_lcov_dir : str | Path | None
        Local directory for pulled .info files.  Created on demand.
    stagnation_window : int
        Number of iterations without coverage increase before declaring
        stagnation.
    gcov_flush_cmd : str
        Shell command executed inside the container to flush gcov counters
        (typically ``kill -USR1 1`` for PID-1 targets compiled with gcov).
    """

    def __init__(
        self,
        container_id: str,
        gcov_prefix: str,
        local_lcov_dir: str | Path | None = None,
        stagnation_window: int = 500,
        gcov_flush_cmd: str = "kill -USR1 1",
    ) -> None:
        self.container_id = container_id
        self.gcov_prefix = gcov_prefix
        self.local_lcov_dir = Path(local_lcov_dir or tempfile.mkdtemp(prefix="fuzzlab_lcov_"))
        self.local_lcov_dir.mkdir(parents=True, exist_ok=True)
        self.stagnation_window = stagnation_window
        self.gcov_flush_cmd = gcov_flush_cmd

        # Rolling history for stagnation detection
        self._path_history: Deque[int] = deque(maxlen=stagnation_window)
        self._peak_unique_paths: int = 0
        self._iteration: int = 0

        # Track every unique coverage hash we have ever seen
        self._seen_hashes: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def pull_gcov_data(self) -> CoverageSnapshot:
        """Flush gcov inside the container, run lcov, pull the .info file,
        and return a parsed CoverageSnapshot."""
        self._iteration += 1

        # 1. Flush gcov counters
        self._exec_in_container(self.gcov_flush_cmd)

        # 2. Run lcov inside container to capture current coverage
        info_filename = f"coverage_{self._iteration}.info"
        container_info_path = f"/tmp/{info_filename}"

        lcov_cmd = (
            f"lcov --capture --directory {self.gcov_prefix} "
            f"--output-file {container_info_path} "
            f"--rc lcov_branch_coverage=1 "
            f"--quiet"
        )
        self._exec_in_container(lcov_cmd)

        # 3. Copy .info file from container to local filesystem
        local_info_path = self.local_lcov_dir / info_filename
        self._copy_from_container(container_info_path, local_info_path)

        # 4. Parse
        snapshot = LcovParser.parse_file(local_info_path, iteration=self._iteration)

        # 5. Update stagnation tracker
        self._path_history.append(snapshot.unique_paths)
        self._peak_unique_paths = max(self._peak_unique_paths, snapshot.unique_paths)

        # 6. Track unique coverage hashes
        h = snapshot.coverage_hash()
        is_new = h not in self._seen_hashes
        if is_new:
            self._seen_hashes.add(h)
            logger.debug(
                "New coverage hash %s at iter %d (paths=%d)",
                h, self._iteration, snapshot.unique_paths,
            )

        # 7. Clean up container-side temp file to avoid filling /tmp
        self._exec_in_container(f"rm -f {container_info_path}", check=False)

        return snapshot

    def get_unique_paths(self) -> int:
        """Return the most recently observed unique-path count."""
        if not self._path_history:
            return 0
        return self._path_history[-1]

    def get_peak_unique_paths(self) -> int:
        return self._peak_unique_paths

    def is_stagnant(self, window: Optional[int] = None) -> bool:
        """Return True if coverage has not increased in the last *window*
        iterations.

        The detector compares the maximum unique-path count in the window
        against the all-time peak.  If the window max equals the peak for
        *window* consecutive readings, we declare stagnation.
        """
        w = window or self.stagnation_window
        if len(self._path_history) < w:
            return False

        recent = list(self._path_history)[-w:]
        window_max = max(recent)
        window_min = min(recent)

        # No new paths discovered — flat line
        if window_max == window_min and window_max == self._peak_unique_paths:
            logger.info(
                "Coverage stagnation detected: %d unique paths unchanged "
                "over last %d iterations.",
                window_max, w,
            )
            return True

        return False

    def get_coverage_delta(self, old: CoverageSnapshot, new: CoverageSnapshot) -> Dict:
        """Compute the delta between two snapshots.

        Returns a dict with counts of new lines hit, new branches hit,
        and the list of newly-covered source files.
        """
        old_lines: Set[Tuple[str, int]] = set()
        new_lines: Set[Tuple[str, int]] = set()

        for sf, fc in old.file_coverages.items():
            for ln, cnt in fc.line_details.items():
                if cnt > 0:
                    old_lines.add((sf, ln))

        for sf, fc in new.file_coverages.items():
            for ln, cnt in fc.line_details.items():
                if cnt > 0:
                    new_lines.add((sf, ln))

        gained_lines = new_lines - old_lines
        lost_lines = old_lines - new_lines  # should be 0 normally

        gained_files = {sf for sf, _ in gained_lines} - {sf for sf, _ in old_lines}

        return {
            "new_lines_hit": len(gained_lines),
            "lost_lines_hit": len(lost_lines),
            "new_files_covered": sorted(gained_files),
            "delta_line_pct": new.line_coverage_pct - old.line_coverage_pct,
            "delta_branch_pct": new.branch_coverage_pct - old.branch_coverage_pct,
        }

    def reset_counters(self) -> None:
        """Zero out gcov counters inside the container (useful between runs)."""
        cmd = f"lcov --zerocounters --directory {self.gcov_prefix} --quiet"
        self._exec_in_container(cmd)
        self._path_history.clear()
        self._peak_unique_paths = 0
        self._seen_hashes.clear()
        self._iteration = 0
        logger.info("Coverage counters reset in container %s", self.container_id)

    @property
    def unique_coverage_hashes_count(self) -> int:
        """How many distinct coverage bitmaps have we observed so far."""
        return len(self._seen_hashes)

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------

    def _exec_in_container(self, cmd: str, check: bool = True) -> str:
        """Run a shell command inside the Docker container via docker exec."""
        full_cmd = ["docker", "exec", self.container_id, "sh", "-c", cmd]
        logger.debug("docker exec %s: %s", self.container_id, cmd)
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=check,
            )
            if result.returncode != 0 and check:
                logger.warning(
                    "Container command failed (rc=%d): %s\nstderr: %s",
                    result.returncode, cmd, result.stderr.strip(),
                )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.error("Timed out running command in container: %s", cmd)
            raise
        except subprocess.CalledProcessError as exc:
            logger.error(
                "Command failed in container (rc=%d): %s\nstderr: %s",
                exc.returncode, cmd, exc.stderr.strip() if exc.stderr else "",
            )
            raise

    def _copy_from_container(self, src: str, dst: Path) -> None:
        """Copy a file from the container to the local filesystem."""
        full_cmd = ["docker", "cp", f"{self.container_id}:{src}", str(dst)]
        logger.debug("docker cp %s:%s -> %s", self.container_id, src, dst)
        subprocess.run(full_cmd, capture_output=True, check=True, timeout=30)
