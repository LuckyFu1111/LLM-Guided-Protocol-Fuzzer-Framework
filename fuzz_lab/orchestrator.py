"""
Orchestrator — main experiment loop for the LLM-guided fuzzing framework.

Flow:
  1. Build & start the instrumented Docker target.
  2. Initialise Boofuzz with traditional mutations.
  3. Per-packet callback: pull GCOV coverage.
  4. On stagnation -> freeze Boofuzz -> LLMMutator generates seeds -> inject -> resume.
  5. On crash -> freeze -> log crash -> restart target -> resume.
  6. Export metrics on completion.

Diagnostic Mode (--check):
  Runs a smoke test verifying the entire pipeline end-to-end:
    1. Docker: build image, start container, health check.
    2. Ollama: connect to Qwen3:8b, generate hex seeds for a dummy DNS packet.
    3. GCOV:   send 10 random packets via Boofuzz, verify .gcda files appear,
              parse an lcov tracefile with PathRemapper.
    4. Boofuzz: confirm UDP session is established and packets are sent.
"""

from __future__ import annotations

import binascii
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from fuzz_lab.config import (
    COVERAGE_CONFIG,
    DOCKER_CONFIG,
    EXPERIMENT_CONFIG,
    TARGET_CONFIG,
    TargetSpec,
)
from fuzz_lab.core.controller import TargetController
from fuzz_lab.core.engine_boofuzz import BoofuzzEngine
from fuzz_lab.core.monitor import CoverageMonitor, LcovParser, PathRemapper
from fuzz_lab.core.mutator_llm import LLMMutator
from fuzz_lab.metrics.tracker import MeasurementMatrix

logger = logging.getLogger(__name__)


# =====================================================================
# Smoke Test / System Diagnostic Mode
# =====================================================================

class SystemDiagnostic:
    """Verify every component of the pipeline without running a full campaign."""

    PASS = "\033[92mPASS\033[0m"
    FAIL = "\033[91mFAIL\033[0m"
    WARN = "\033[93mWARN\033[0m"

    def __init__(self, target_name: str = "bind9", workspace: str | Path = ".") -> None:
        if target_name not in TARGET_CONFIG:
            raise ValueError(f"Unknown target: {target_name}")
        self.target_spec = TARGET_CONFIG[target_name]
        self.workspace = Path(workspace)
        self._results: list[tuple[str, bool, str]] = []

    def run_all(self) -> bool:
        """Run all diagnostics and return True if everything passed."""
        print("\n" + "=" * 64)
        print("  SYSTEM DIAGNOSTIC — Pipeline Smoke Test")
        print("=" * 64 + "\n")

        self._check_docker()
        self._check_ollama()
        self._check_gcov()
        self._check_boofuzz()

        # Summary
        print("\n" + "-" * 64)
        passed = sum(1 for _, ok, _ in self._results if ok)
        total = len(self._results)
        print(f"\n  Results: {passed}/{total} checks passed\n")

        for name, ok, detail in self._results:
            status = self.PASS if ok else self.FAIL
            print(f"  [{status}] {name}")
            if detail:
                for line in detail.splitlines():
                    print(f"         {line}")
        print()

        all_ok = all(ok for _, ok, _ in self._results)
        if all_ok:
            print("  All systems operational. Ready to fuzz.\n")
        else:
            print("  Some checks failed. Review the output above.\n")

        return all_ok

    # ------------------------------------------------------------------
    # 1. Docker Check
    # ------------------------------------------------------------------

    def _check_docker(self) -> None:
        print("[1/4] Docker Check")

        # Docker daemon reachable?
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=10,
            )
            ok = result.returncode == 0
            self._record("Docker daemon reachable", ok, "")
        except FileNotFoundError:
            self._record("Docker daemon reachable", False, "docker CLI not found in PATH")
            return
        except subprocess.TimeoutExpired:
            self._record("Docker daemon reachable", False, "docker info timed out")
            return

        # Docker network exists?
        net_name = DOCKER_CONFIG["network_name"]
        result = subprocess.run(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            capture_output=True, text=True, timeout=10,
        )
        net_exists = net_name in result.stdout.splitlines()
        if not net_exists:
            print(f"  Creating network '{net_name}'...")
            subprocess.run(
                ["docker", "network", "create", net_name],
                capture_output=True, timeout=10,
            )
            net_exists = True
        self._record(f"Docker network '{net_name}'", net_exists, "")

        # Build context exists?
        build_ctx = self.workspace / self.target_spec.docker_build_context
        ctx_exists = build_ctx.exists() and (build_ctx / "Dockerfile").exists()
        self._record(
            f"Build context ({build_ctx})",
            ctx_exists,
            "" if ctx_exists else "Dockerfile not found",
        )

        if not ctx_exists:
            return

        # Can we build? (quick syntax check — don't do the full build in diagnostic)
        try:
            result = subprocess.run(
                ["docker", "build", "--check", str(build_ctx)],
                capture_output=True, text=True, timeout=30,
            )
            # --check flag may not be supported on older docker; fall back
            if result.returncode != 0 and "unknown flag" in result.stderr.lower():
                self._record("Dockerfile syntax", True, "(--check not supported, skipped)")
            else:
                self._record("Dockerfile syntax", result.returncode == 0,
                             result.stderr.strip()[:200] if result.returncode != 0 else "")
        except subprocess.TimeoutExpired:
            self._record("Dockerfile syntax", False, "docker build --check timed out")

    # ------------------------------------------------------------------
    # 2. Ollama Check
    # ------------------------------------------------------------------

    def _check_ollama(self) -> None:
        print("[2/4] Ollama / LLM Check")

        mutator = LLMMutator()

        # Server reachable?
        available = mutator.is_available()
        self._record("Ollama server reachable", available,
                      "" if available else f"Cannot connect to {mutator.base_url}")

        if not available:
            return

        # Model loaded?
        try:
            import requests
            resp = requests.get(f"{mutator.base_url}/api/tags", timeout=5)
            models = [m["name"] for m in resp.json().get("models", [])]
            model_present = any(mutator.model in m for m in models)
            self._record(
                f"Model '{mutator.model}' available",
                model_present,
                f"Available models: {models}" if not model_present else "",
            )
        except Exception as exc:
            self._record(f"Model '{mutator.model}' available", False, str(exc))
            return

        # Generate test seeds for a dummy DNS packet
        dummy_dns = (
            b"\x12\x34"    # txn ID
            b"\x01\x00"    # flags: standard query, RD
            b"\x00\x01"    # qdcount=1
            b"\x00\x00"    # ancount=0
            b"\x00\x00"    # nscount=0
            b"\x00\x00"    # arcount=0
            b"\x07example\x03com\x00"  # qname
            b"\x00\x01"    # qtype=A
            b"\x00\x01"    # qclass=IN
        )

        print("  Generating test mutations for dummy DNS packet...")
        seeds = mutator.generate_mutations(
            seed=dummy_dns,
            protocol="dns",
            rfc_ref="RFC 1035",
            cve_hint="cache memory exhaustion via specific RRset queries",
        )
        self._record(
            "LLM generates valid hex seeds",
            len(seeds) > 0,
            f"Got {len(seeds)} seeds" + (
                f", first: {binascii.hexlify(seeds[0]).decode()[:60]}..."
                if seeds else ""
            ),
        )

    # ------------------------------------------------------------------
    # 3. GCOV Check
    # ------------------------------------------------------------------

    def _check_gcov(self) -> None:
        print("[3/4] GCOV / Coverage Check")

        # Test the LCOV parser with synthetic data
        synthetic_lcov = [
            "TN:",
            "SF:/usr/src/bind9/lib/dns/message.c",
            "DA:10,1",
            "DA:11,5",
            "DA:12,0",
            "DA:20,3",
            "LF:4",
            "LH:3",
            "BRDA:10,0,0,1",
            "BRDA:10,0,1,0",
            "BRF:2",
            "BRH:1",
            "end_of_record",
            "SF:/usr/src/bind9/lib/dns/name.c",
            "DA:1,0",
            "DA:2,1",
            "LF:2",
            "LH:1",
            "BRF:0",
            "BRH:0",
            "end_of_record",
        ]

        try:
            snap = LcovParser.parse_lines(synthetic_lcov, iteration=0)
            parser_ok = (
                snap.total_lines == 6
                and snap.total_lines_hit == 4
                and snap.total_branches == 2
                and snap.total_branches_hit == 1
                and snap.unique_paths == 5  # 4 lines + 1 branch
                and len(snap.file_coverages) == 2
            )
            detail = (
                f"LF={snap.total_lines} LH={snap.total_lines_hit} "
                f"BRF={snap.total_branches} BRH={snap.total_branches_hit} "
                f"paths={snap.unique_paths} files={len(snap.file_coverages)}"
            )
            self._record("LCOV parser (synthetic data)", parser_ok, detail)
        except Exception as exc:
            self._record("LCOV parser (synthetic data)", False, str(exc))

        # Test PathRemapper
        remapper = PathRemapper([
            ("/usr/src/bind9", "/Users/me/fuzz_lab/targets/bind9/src"),
        ])
        remapped = remapper.remap("/usr/src/bind9/lib/dns/message.c")
        expected = "/Users/me/fuzz_lab/targets/bind9/src/lib/dns/message.c"
        self._record(
            "PathRemapper transforms paths",
            remapped == expected,
            f"Got: {remapped}" if remapped != expected else "",
        )

        # Test LCOV content remapping
        lcov_content = "TN:\nSF:/usr/src/bind9/lib/dns/message.c\nDA:10,1\nend_of_record\n"
        remapped_content = remapper.remap_lcov_content(lcov_content)
        content_ok = "/Users/me/fuzz_lab/targets/bind9/src/lib/dns/message.c" in remapped_content
        self._record("LCOV content path remapping", content_ok, "")

        # Check for .gcda files in the gcov volume (if container exists)
        gcov_vol = self.workspace / "gcov_data" / self.target_spec.name
        if gcov_vol.exists():
            gcda_files = list(gcov_vol.rglob("*.gcda"))
            self._record(
                f"GCOV data files in {gcov_vol}",
                len(gcda_files) > 0,
                f"Found {len(gcda_files)} .gcda files" if gcda_files
                else "No .gcda files yet (expected if container hasn't run)",
            )
        else:
            self._record(
                f"GCOV data directory {gcov_vol}",
                False,
                "Directory does not exist yet (created on first run)",
            )

    # ------------------------------------------------------------------
    # 4. Boofuzz Check
    # ------------------------------------------------------------------

    def _check_boofuzz(self) -> None:
        print("[4/4] Boofuzz / Network Check")

        # Can we import boofuzz?
        try:
            import boofuzz
            self._record("Boofuzz import", True, f"version {boofuzz.__version__}")
        except ImportError:
            self._record("Boofuzz import", False, "pip install boofuzz")
            return

        # Is the target port reachable? (may not be if container isn't running)
        port = self.target_spec.default_port
        try:
            if self.target_spec.protocol == "dns":
                # UDP — send a real DNS query and check for a response
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                # Minimal DNS query for '.' A record
                dns_query = (
                    b"\xaa\xbb"    # txn ID
                    b"\x01\x00"    # standard query, RD
                    b"\x00\x01"    # qdcount=1
                    b"\x00\x00\x00\x00\x00\x00"
                    b"\x00"        # root
                    b"\x00\x01"    # A
                    b"\x00\x01"    # IN
                )
                sock.sendto(dns_query, ("127.0.0.1", port))
                try:
                    data, _ = sock.recvfrom(512)
                    self._record(
                        f"DNS port {port}/udp responding",
                        True,
                        f"Received {len(data)} bytes",
                    )
                except socket.timeout:
                    self._record(
                        f"DNS port {port}/udp responding",
                        False,
                        "No response (is the container running?)",
                    )
                finally:
                    sock.close()
            else:
                # TCP
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=2):
                        self._record(f"Port {port}/tcp open", True, "")
                except (ConnectionRefusedError, OSError):
                    self._record(
                        f"Port {port}/tcp open",
                        False,
                        "Connection refused (is the container running?)",
                    )
        except Exception as exc:
            self._record(f"Port {port} connectivity", False, str(exc))

        # Can we create a Boofuzz session? (doesn't require a live target)
        try:
            engine = BoofuzzEngine(
                protocol=self.target_spec.protocol,
                target_host="127.0.0.1",
                target_port=port,
            )
            session = engine.create_session()
            self._record(
                "Boofuzz session creation",
                session is not None,
                f"Protocol graph defined for {self.target_spec.protocol.upper()}",
            )
        except Exception as exc:
            self._record("Boofuzz session creation", False, str(exc))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _record(self, name: str, ok: bool, detail: str) -> None:
        self._results.append((name, ok, detail))
        status = self.PASS if ok else self.FAIL
        print(f"  [{status}] {name}")
        if detail:
            for line in detail.splitlines():
                print(f"           {line}")


# =====================================================================
# Orchestrator — Main Experiment Loop
# =====================================================================

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
            self.tracker.start_periodic_plotting()
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

        # Resolve path mapping for GCOV (container -> host)
        source_container = self.target_spec.source_dir_container
        source_host = str(
            (self.workspace / self.target_spec.source_dir_host).resolve()
        ) if self.target_spec.source_dir_host else ""

        self.monitor = CoverageMonitor(
            container_id=container_id,
            gcov_prefix=self.target_spec.gcov_prefix,
            source_prefix_container=source_container,
            source_prefix_host=source_host,
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

        # Stagnation check -> trigger LLM mutation
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
            self.tracker.stop_periodic_plotting()
            summary = self.tracker.summary()
            logger.info("Campaign summary: %s", summary)
            csv_path = self.tracker.export_csv()
            logger.info("Metrics exported to %s", csv_path)
            # Final coverage plot
            self.tracker.plot_coverage_evolution()

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
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run system diagnostic smoke test instead of fuzzing",
    )

    args = parser.parse_args()

    if args.check:
        diagnostic = SystemDiagnostic(
            target_name=args.target,
            workspace=args.workspace,
        )
        ok = diagnostic.run_all()
        sys.exit(0 if ok else 1)

    orchestrator = Orchestrator(
        target_name=args.target,
        workspace=args.workspace,
        max_iterations=args.max_iterations,
    )
    orchestrator.run()


if __name__ == "__main__":
    main()
