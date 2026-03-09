"""
CoverageMonitor — GCOV/LCOV integration for coverage-guided fuzzing.

Responsibilities:
  1. Trigger gcov data flush inside the Docker container.
  2. Run lcov to collect coverage into a .info tracefile.
  3. Remap container-absolute paths to host-relative paths so host-side
     tools (lcov, genhtml) can resolve source files.
  4. Parse the tracefile to extract total lines, lines hit, branches hit,
     and unique-path counts.
  5. Detect stagnation (no new coverage in a sliding window of iterations).

Path Remapping Problem:
  GCOV/LCOV tracefiles contain absolute paths as they exist *inside* the
  container, e.g.  ``SF:/usr/src/bind9/lib/dns/message.c``
  On the macOS host the source tree lives at a different location, e.g.
  ``/Users/me/fuzz_lab/targets/bind9/src/lib/dns/message.c``
  The PathRemapper rewrites SF: lines before parsing so that all downstream
  consumers see host-relative paths.

Retry Logic:
  GCOV .gcda files may be locked or temporarily empty while the target
  process is in the middle of a write.  All file operations that touch
  coverage data retry with exponential backoff.
"""

from __future__ import annotations

import hashlib
import logging
import re
import subprocess
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Default retry parameters for GCOV file operations
_GCOV_MAX_RETRIES = 4
_GCOV_BACKOFF_BASE = 0.5  # seconds; retries at 0.5, 1, 2, 4s


# ---------------------------------------------------------------------------
# Path Remapper
# ---------------------------------------------------------------------------

class PathRemapper:
    """Rewrite container-absolute paths in LCOV tracefiles to host paths.

    Parameters
    ----------
    mappings : list of (container_prefix, host_prefix) tuples
        Each pair maps a container path prefix to its host-side equivalent.
        Evaluated in order; first match wins.

    Example::

        remapper = PathRemapper([
            ("/usr/src/bind9", "/Users/me/fuzz_lab/targets/bind9/src"),
        ])
        host_path = remapper.remap("/usr/src/bind9/lib/dns/message.c")
        # -> "/Users/me/fuzz_lab/targets/bind9/src/lib/dns/message.c"
    """

    def __init__(self, mappings: List[Tuple[str, str]] | None = None) -> None:
        # Normalise: strip trailing slashes for consistent prefix matching
        self.mappings: List[Tuple[str, str]] = []
        for container_pfx, host_pfx in (mappings or []):
            self.mappings.append((
                container_pfx.rstrip("/"),
                host_pfx.rstrip("/"),
            ))

    def remap(self, container_path: str) -> str:
        """Return the host-side path for a container-absolute path.

        If no mapping matches, the original path is returned unchanged.
        """
        for container_pfx, host_pfx in self.mappings:
            if container_path.startswith(container_pfx):
                suffix = container_path[len(container_pfx):]
                return host_pfx + suffix
        return container_path

    def remap_lcov_content(self, content: str) -> str:
        """Rewrite every ``SF:`` line in an LCOV tracefile string."""
        lines = content.splitlines(keepends=True)
        out: list[str] = []
        for line in lines:
            if line.startswith("SF:"):
                original = line[3:].rstrip("\n\r")
                remapped = self.remap(original)
                out.append(f"SF:{remapped}\n")
            else:
                out.append(line)
        return "".join(out)

    def remap_lcov_file(self, info_path: Path) -> None:
        """In-place rewrite of SF: lines in an LCOV .info file on disk."""
        content = info_path.read_text(encoding="utf-8", errors="replace")
        remapped = self.remap_lcov_content(content)
        if remapped != content:
            info_path.write_text(remapped, encoding="utf-8")
            logger.debug("Remapped paths in %s", info_path)


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
    """Parse an LCOV .info tracefile into a CoverageSnapshot.

    Optionally applies path remapping before parsing so that SF: lines
    reference host-side paths instead of container-internal paths.
    """

    # Precompiled regexes for hot-path parsing
    _RE_DA = re.compile(r"^DA:(\d+),(\d+)")
    _RE_BRDA = re.compile(r"^BRDA:(\d+),(\d+),(\d+),(-|\d+)")

    @classmethod
    def parse_file(
        cls,
        info_path: str | Path,
        iteration: int = 0,
        remapper: PathRemapper | None = None,
    ) -> CoverageSnapshot:
        """Read an lcov .info file from disk and return a CoverageSnapshot.

        Parameters
        ----------
        info_path : path
            Local path to the .info tracefile.
        iteration : int
            Current fuzzing iteration (for bookkeeping).
        remapper : PathRemapper, optional
            If provided, SF: lines are rewritten before parsing.
        """
        info_path = Path(info_path)
        if not info_path.exists():
            raise FileNotFoundError(f"LCOV tracefile not found: {info_path}")

        content = info_path.read_text(encoding="utf-8", errors="replace")

        # Apply path remapping if configured
        if remapper:
            content = remapper.remap_lcov_content(content)

        return cls.parse_lines(content.splitlines(), iteration=iteration)

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
# Retry helper
# ---------------------------------------------------------------------------

def _retry_operation(
    operation,
    description: str,
    max_retries: int = _GCOV_MAX_RETRIES,
    backoff_base: float = _GCOV_BACKOFF_BASE,
):
    """Execute *operation* with retries and exponential backoff.

    Catches OSError (file locked / empty / permission) and
    subprocess.CalledProcessError (lcov transient failure).
    """
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            return operation()
        except (OSError, subprocess.CalledProcessError, FileNotFoundError) as exc:
            last_exc = exc
            wait = backoff_base * (2 ** (attempt - 1))
            logger.warning(
                "%s: attempt %d/%d failed (%s) — retrying in %.1fs",
                description, attempt, max_retries, exc, wait,
            )
            time.sleep(wait)

    logger.error("%s: all %d attempts failed", description, max_retries)
    raise last_exc  # type: ignore[misc]


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
    source_prefix_container : str
        Absolute path to the source tree *inside* the container
        (e.g. ``/usr/src/bind9``).
    source_prefix_host : str
        Corresponding path on the host (e.g. ``./targets/bind9/src``).
        Pass empty string to disable remapping.
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
        source_prefix_container: str = "",
        source_prefix_host: str = "",
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

        # Path remapping (container paths → host paths)
        mappings: List[Tuple[str, str]] = []
        if source_prefix_container and source_prefix_host:
            mappings.append((source_prefix_container, source_prefix_host))
        self._remapper = PathRemapper(mappings) if mappings else None

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
        and return a parsed CoverageSnapshot.

        All file I/O uses retry logic to handle locked/empty .gcda files
        that occur when the target is mid-write.
        """
        self._iteration += 1

        # 1. Flush gcov counters (retry — the process may be busy)
        _retry_operation(
            lambda: self._exec_in_container(self.gcov_flush_cmd),
            description="gcov flush",
        )

        # Small delay to let .gcda files finish writing on VirtioFS
        time.sleep(0.2)

        # 2. Run lcov inside container to capture current coverage
        info_filename = f"coverage_{self._iteration}.info"
        container_info_path = f"/tmp/{info_filename}"

        lcov_cmd = (
            f"lcov --capture "
            f"--directory {self.gcov_prefix} "
            f"--base-directory /usr/src/bind9 "
            f"--output-file {container_info_path} "
            f"--rc lcov_branch_coverage=1 "
            f"--no-external "
            f"--quiet"
        )
        _retry_operation(
            lambda: self._exec_in_container(lcov_cmd),
            description="lcov capture",
        )

        # 3. Copy .info file from container to local filesystem (retry)
        local_info_path = self.local_lcov_dir / info_filename
        _retry_operation(
            lambda: self._copy_from_container(container_info_path, local_info_path),
            description="docker cp tracefile",
        )

        # 4. Validate the file isn't empty (transient VirtioFS issue)
        def _parse_with_validation():
            size = local_info_path.stat().st_size
            if size == 0:
                raise OSError(f"Tracefile is empty (0 bytes): {local_info_path}")
            return LcovParser.parse_file(
                local_info_path,
                iteration=self._iteration,
                remapper=self._remapper,
            )

        snapshot = _retry_operation(
            _parse_with_validation,
            description="parse tracefile",
        )

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

    @property
    def remapper(self) -> PathRemapper | None:
        return self._remapper

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
