"""
CrashTriager — automated crash analysis and CVE matching.

When the fuzzer detects a crash (target process dies), this module:
  1. Runs gdb inside the container to capture a backtrace.
  2. Extracts the crashing function and file from the backtrace.
  3. Matches the crash location against the ``affected_component`` field
     in the CVE catalog to identify which vulnerability was likely triggered.
  4. Returns a structured TriageResult for logging and metrics.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from fuzz_lab.config import CVEEntry, TargetSpec

logger = logging.getLogger(__name__)

# Timeout for gdb commands inside the container
_GDB_TIMEOUT = 30


@dataclass
class TriageResult:
    """Structured output from crash triage."""
    crash_signal: int
    backtrace: str
    crashing_function: str = ""
    crashing_file: str = ""
    crashing_line: int = 0
    matched_cves: List[CVEEntry] = field(default_factory=list)
    confidence: str = "none"  # "high", "medium", "low", "none"


class CrashTriager:
    """Analyze crashes inside a Docker container and match to known CVEs.

    Parameters
    ----------
    target_spec : TargetSpec
        Target configuration with CVE catalog and component mapping.
    """

    # Regex to extract frames from gdb backtrace output.
    # Matches lines like:
    #   #0  0x00005555... in dns_message_parse (msg=0x...) at lib/dns/message.c:1234
    #   #1  0x00005555... in query_find () at lib/dns/query.c:567
    _RE_BT_FRAME = re.compile(
        r"#(\d+)\s+"           # frame number
        r"(?:0x[0-9a-f]+\s+in\s+)?"  # optional address
        r"(\w+)"               # function name
        r"\s*\([^)]*\)"        # arguments (ignored)
        r"(?:\s+at\s+"         # "at" keyword
        r"([^\s:]+)"           # file path
        r":(\d+))?"            # line number
    )

    # Regex for signal information in gdb output
    _RE_SIGNAL = re.compile(
        r"Program received signal (\w+)"
    )

    # Signal name -> number mapping
    _SIGNAL_MAP = {
        "SIGSEGV": 11,
        "SIGABRT": 6,
        "SIGFPE": 8,
        "SIGBUS": 7,
        "SIGILL": 4,
        "SIGTRAP": 5,
    }

    def __init__(self, target_spec: TargetSpec) -> None:
        self.target_spec = target_spec
        self._cve_component_map = self._build_component_index()

    def _build_component_index(self) -> dict[str, list[CVEEntry]]:
        """Build an index mapping file/component substrings to CVEs."""
        index: dict[str, list[CVEEntry]] = {}
        for cve in self.target_spec.cves:
            comp = cve.affected_component
            if not comp:
                continue
            # Normalise: strip leading slashes, src/ prefixes
            comp_norm = comp.lstrip("/").replace("src/", "")
            if comp_norm not in index:
                index[comp_norm] = []
            index[comp_norm].append(cve)
        return index

    def triage_crash(
        self,
        container_id: str,
        crash_input: bytes,
        crash_signal: int = 11,
    ) -> TriageResult:
        """Run gdb in the container and analyze the crash.

        Parameters
        ----------
        container_id : str
            Docker container ID (may be stopped — gdb attaches to core).
        crash_input : bytes
            The input that caused the crash (for logging).
        crash_signal : int
            Detected signal number (default: SIGSEGV=11).

        Returns
        -------
        TriageResult
            Structured crash analysis including CVE matches.
        """
        result = TriageResult(crash_signal=crash_signal)

        # Step 1: Get backtrace via gdb
        backtrace = self._capture_backtrace(container_id)
        result.backtrace = backtrace

        if not backtrace:
            logger.warning("Could not capture backtrace from container %s", container_id)
            return result

        # Step 2: Parse the backtrace
        frames = self._parse_backtrace(backtrace)
        if frames:
            # The top frame (index 0) is where the crash happened
            func, file_path, line = frames[0]
            result.crashing_function = func
            result.crashing_file = file_path
            result.crashing_line = line

        # Step 3: Extract signal from gdb output
        sig_match = self._RE_SIGNAL.search(backtrace)
        if sig_match:
            sig_name = sig_match.group(1)
            result.crash_signal = self._SIGNAL_MAP.get(sig_name, crash_signal)

        # Step 4: Match against CVE catalog
        result.matched_cves, result.confidence = self._match_cves(frames)

        # Log findings
        if result.matched_cves:
            cve_ids = [c.cve_id for c in result.matched_cves]
            logger.info(
                "Crash triage: %s in %s:%d — matched CVEs: %s (confidence: %s)",
                result.crashing_function, result.crashing_file,
                result.crashing_line, cve_ids, result.confidence,
            )
        else:
            logger.info(
                "Crash triage: %s in %s:%d — no CVE match",
                result.crashing_function, result.crashing_file,
                result.crashing_line,
            )

        return result

    def _capture_backtrace(self, container_id: str) -> str:
        """Run gdb inside the container to get a backtrace.

        Attempts multiple strategies:
          1. Attach to the crashed process's core dump.
          2. If no core, look at the most recent process state.
        """
        # Find the main binary path based on target
        binary_paths = {
            "bind9": "/opt/bind9/sbin/named",
            "mosquitto": "/usr/local/mosquitto/sbin/mosquitto",
        }
        binary = binary_paths.get(self.target_spec.name, "")

        # Strategy 1: Look for core dump
        backtrace = self._gdb_from_core(container_id, binary)
        if backtrace:
            return backtrace

        # Strategy 2: Get backtrace from the process if it's still in a
        # crash state (some signals leave the process running)
        backtrace = self._gdb_attach_pid1(container_id, binary)
        if backtrace:
            return backtrace

        # Strategy 3: Use dmesg to find crash info
        return self._dmesg_crash_info(container_id)

    def _gdb_from_core(self, container_id: str, binary: str) -> str:
        """Try to analyze a core dump with gdb."""
        gdb_script = (
            f"gdb -batch -quiet "
            f"-ex 'set pagination off' "
            f"-ex 'bt full 20' "
            f"-ex 'info registers' "
            f"-ex 'quit' "
            f"{binary} /tmp/core 2>/dev/null || true"
        )

        # First check if a core dump exists
        check_cmd = "ls /tmp/core* /var/crash/* 2>/dev/null | head -1"
        core_path = self._exec_container(container_id, check_cmd).strip()

        if not core_path:
            return ""

        # Replace the path in gdb command
        gdb_cmd = gdb_script.replace("/tmp/core", core_path)
        return self._exec_container(container_id, gdb_cmd)

    def _gdb_attach_pid1(self, container_id: str, binary: str) -> str:
        """Attach gdb to PID 1 (the main process) to get a backtrace."""
        gdb_script = (
            "gdb -batch -quiet "
            "-ex 'set pagination off' "
            "-ex 'thread apply all bt 20' "
            "-ex 'quit' "
            f"-p 1 2>/dev/null || true"
        )
        return self._exec_container(container_id, gdb_script)

    def _dmesg_crash_info(self, container_id: str) -> str:
        """Fall back to dmesg for crash information."""
        cmd = "dmesg 2>/dev/null | tail -20 || journalctl -k -n 20 2>/dev/null || true"
        return self._exec_container(container_id, cmd)

    def _parse_backtrace(self, backtrace: str) -> List[Tuple[str, str, int]]:
        """Extract (function, file, line) tuples from a gdb backtrace.

        Returns frames ordered from top (crash site) to bottom (main).
        """
        frames: List[Tuple[str, str, int]] = []

        for match in self._RE_BT_FRAME.finditer(backtrace):
            func = match.group(2)
            file_path = match.group(3) or ""
            line_no = int(match.group(4)) if match.group(4) else 0
            frames.append((func, file_path, line_no))

        # Sort by frame number (should already be in order)
        return frames

    def _match_cves(
        self,
        frames: List[Tuple[str, str, int]],
    ) -> Tuple[List[CVEEntry], str]:
        """Match backtrace frames against the CVE catalog.

        Matching strategy:
          - High confidence: crash file exactly matches affected_component.
          - Medium confidence: crash file is a substring match.
          - Low confidence: a non-top frame matches.

        Returns (matched_cves, confidence_level).
        """
        if not frames:
            return [], "none"

        matched: List[CVEEntry] = []
        best_confidence = "none"

        for frame_idx, (func, file_path, _line) in enumerate(frames):
            if not file_path:
                continue

            # Normalise the file path for matching
            file_norm = file_path.lstrip("/").replace("src/", "")

            for comp_key, cves in self._cve_component_map.items():
                # Exact match (highest confidence)
                if file_norm == comp_key or file_norm.endswith(comp_key):
                    for cve in cves:
                        if cve not in matched:
                            matched.append(cve)
                    if frame_idx == 0:
                        best_confidence = "high"
                    elif best_confidence != "high":
                        best_confidence = "low"

                # Partial match: the component is a directory/module name
                elif comp_key in file_norm or file_norm in comp_key:
                    for cve in cves:
                        if cve not in matched:
                            matched.append(cve)
                    if frame_idx == 0 and best_confidence not in ("high",):
                        best_confidence = "medium"
                    elif best_confidence == "none":
                        best_confidence = "low"

        return matched, best_confidence

    def _exec_container(self, container_id: str, cmd: str) -> str:
        """Execute a command inside the Docker container."""
        full_cmd = ["docker", "exec", container_id, "sh", "-c", cmd]
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=_GDB_TIMEOUT,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as exc:
            logger.debug("Container exec failed: %s", exc)
            return ""
