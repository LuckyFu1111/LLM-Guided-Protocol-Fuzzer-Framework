"""
Orchestrator — main experiment loop for the LLM-guided fuzzing framework.

Flow:
  1. Build & start the instrumented Docker target.
  2. Initialise Boofuzz with traditional mutations.
  3. Per-packet callback: pull GCOV coverage.
  4. On stagnation → freeze Boofuzz → LLMMutator generates seeds → inject → resume.
  5. On crash → freeze → log crash → restart target → resume.
  6. Export metrics on completion.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from fuzz_lab.config import (
    COVERAGE_CONFIG,
    EXPERIMENT_CONFIG,
    TARGET_CONFIG,
    TargetSpec,
)
from fuzz_lab.core.controller import TargetController
from fuzz_lab.core.engine_boofuzz import BoofuzzEngine
from fuzz_lab.core.monitor import CoverageMonitor
from fuzz_lab.core.mutator_llm import LLMMutator
from fuzz_lab.metrics.tracker import MeasurementMatrix

logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinate fuzzing, coverage monitoring, LLM mutation, and metrics."""

    def __init__(
        self,
        target_name: str,
        workspace: str | Path = ".",
        max_iterations: int = EXPERIMENT_CONFIG["max_iterations"],
    ) -> None:
        if target_name not in TARGET_CONFIG:
            raise ValueError(
                f"Unknown target '{target_name}'. "
                f"Available: {list(TARGET_CONFIG.keys())}"
            )

        self.target_spec: TargetSpec = TARGET_CONFIG[target_name]
        self.workspace = Path(workspace)
        self.max_iterations = max_iterations

        # Components (initialised lazily in run())
        self.controller: Optional[TargetController] = None
        self.monitor: Optional[CoverageMonitor] = None
        self.engine: Optional[BoofuzzEngine] = None
        self.mutator: Optional[LLMMutator] = None
        self.tracker: Optional[MeasurementMatrix] = None

        self._iteration = 0
        self._running = False
        self._last_seed: bytes = b""

    # ------------------------------------------------------------------
    # Main Entry Point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute the full experiment loop."""
        self._setup_logging()
        self._register_signal_handlers()

        logger.info("=" * 60)
        logger.info("Starting fuzz campaign: %s (%s)",
                     self.target_spec.name, self.target_spec.protocol)
        logger.info("=" * 60)

        try:
            self._initialise_components()
            self._build_and_start_target()
            self._run_fuzzing_loop()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception:
            logger.exception("Fatal error in orchestrator")
        finally:
            self._shutdown()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _initialise_components(self) -> None:
        self.controller = TargetController(self.target_spec, self.workspace)
        self.mutator = LLMMutator()
        self.tracker = MeasurementMatrix(
            output_path=EXPERIMENT_CONFIG["metrics_output"],
        )

        # Crash log directory
        crash_dir = Path(EXPERIMENT_CONFIG["crash_log_dir"])
        crash_dir.mkdir(parents=True, exist_ok=True)

    def _build_and_start_target(self) -> None:
        self.controller.build_target()
        container_id = self.controller.start_container()

        self.monitor = CoverageMonitor(
            container_id=container_id,
            gcov_prefix=self.target_spec.gcov_prefix,
            stagnation_window=COVERAGE_CONFIG["stagnation_window"],
            gcov_flush_cmd=COVERAGE_CONFIG["gcov_flush_command"],
        )

        # Zero any stale counters from a previous run
        self.monitor.reset_counters()

    # ------------------------------------------------------------------
    # Core Loop
    # ------------------------------------------------------------------

    def _run_fuzzing_loop(self) -> None:
        """Create the Boofuzz session and drive the feedback loop."""
        self.engine = BoofuzzEngine(
            protocol=self.target_spec.protocol,
            target_host="127.0.0.1",
            target_port=self.target_spec.default_port,
            post_test_callback=self._on_post_test_case,
            crash_callback=self._on_crash,
        )

        self.engine.create_session()
        self._running = True
        logger.info("Fuzzing loop started (max %d iterations)", self.max_iterations)

        self.engine.start()

    # ------------------------------------------------------------------
    # Per-Packet Callback
    # ------------------------------------------------------------------

    def _on_post_test_case(self, session, fuzz_data_logger) -> None:
        """Called after every Boofuzz test case to sync coverage."""
        self._iteration += 1
        if self._iteration > self.max_iterations:
            self._running = False
            return

        # Pull coverage
        try:
            snapshot = self.monitor.pull_gcov_data()
        except Exception as exc:
            logger.warning("Coverage pull failed at iter %d: %s",
                           self._iteration, exc)
            return

        # Log to tracker
        self.tracker.log_coverage(
            iteration=self._iteration,
            unique_paths=snapshot.unique_paths,
            line_pct=snapshot.line_coverage_pct,
            branch_pct=snapshot.branch_coverage_pct,
        )

        # Health check
        if not self.controller.get_health():
            self._on_crash(session, fuzz_data_logger)
            return

        # Stagnation check → trigger LLM mutation
        if self.monitor.is_stagnant():
            self._trigger_llm_mutation(snapshot)

    # ------------------------------------------------------------------
    # Crash Handling
    # ------------------------------------------------------------------

    def _on_crash(self, session, fuzz_data_logger) -> None:
        """Freeze, log, restart, resume."""
        logger.warning("Crash at iteration %d", self._iteration)
        self.engine.pause()

        # Capture the crashing input (best-effort)
        crash_input = self._last_seed or b"<unknown>"

        self.tracker.log_crash(
            iteration=self._iteration,
            signal=11,  # SIGSEGV placeholder
            crash_input=crash_input,
        )

        # Save crash artifact
        crash_path = (
            Path(EXPERIMENT_CONFIG["crash_log_dir"])
            / f"crash_{self._iteration}.bin"
        )
        crash_path.write_bytes(crash_input)
        logger.info("Crash input saved to %s", crash_path)

        # Restart target
        new_id = self.controller.restart_on_crash()
        self.monitor.container_id = new_id

        self.engine.resume()

    # ------------------------------------------------------------------
    # LLM Mutation Phase
    # ------------------------------------------------------------------

    def _trigger_llm_mutation(self, snapshot) -> None:
        """Pause traditional fuzzing, generate LLM seeds, inject, resume."""
        logger.info("Coverage stagnant at %d paths — invoking LLM mutator",
                     snapshot.unique_paths)
        self.engine.pause()

        paths_before = snapshot.unique_paths
        seed = self._last_seed or b"\x00" * 16

        # Pick a CVE hint based on weight (cycle through increasing difficulty)
        cve_idx = (self._iteration // COVERAGE_CONFIG["stagnation_window"]) % len(
            self.target_spec.cves
        )
        cve = self.target_spec.cves[cve_idx]
        rfc_ref = (
            self.target_spec.rfc_references[0]
            if self.target_spec.rfc_references else ""
        )

        seeds = self.mutator.generate_mutations(
            seed=seed,
            protocol=self.target_spec.protocol,
            state="",
            rfc_ref=rfc_ref,
            cve_hint=cve.description,
        )

        # Validate seeds (basic: non-empty, minimum length)
        valid_seeds = [s for s in seeds if len(s) >= 2]

        self.tracker.log_llm_batch(
            iteration=self._iteration,
            seeds_requested=self.mutator.batch_size,
            seeds_returned=len(seeds),
            valid_seeds=len(valid_seeds),
            new_paths_discovered=0,  # updated after injection
            traditional_paths_at_time=paths_before,
        )

        if valid_seeds:
            self.engine.inject_seeds(valid_seeds)

        self.engine.resume()

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _shutdown(self) -> None:
        logger.info("Shutting down orchestrator")

        if self.tracker:
            summary = self.tracker.summary()
            logger.info("Campaign summary: %s", summary)
            csv_path = self.tracker.export_csv()
            logger.info("Metrics exported to %s", csv_path)

        if self.controller:
            self.controller.stop_container()

        self._running = False

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, EXPERIMENT_CONFIG["log_level"]),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def _register_signal_handlers(self) -> None:
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame) -> None:
        logger.info("Signal %d received, shutting down gracefully", signum)
        self._running = False


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM-Guided Protocol Fuzzing Framework",
    )
    parser.add_argument(
        "target",
        choices=list(TARGET_CONFIG.keys()),
        help="Target to fuzz (e.g. bind9, mosquitto)",
    )
    parser.add_argument(
        "--max-iterations", "-n",
        type=int,
        default=EXPERIMENT_CONFIG["max_iterations"],
        help="Maximum fuzzing iterations",
    )
    parser.add_argument(
        "--workspace", "-w",
        type=str,
        default=".",
        help="Working directory for build artifacts and logs",
    )

    args = parser.parse_args()

    orchestrator = Orchestrator(
        target_name=args.target,
        workspace=args.workspace,
        max_iterations=args.max_iterations,
    )
    orchestrator.run()


if __name__ == "__main__":
    main()
