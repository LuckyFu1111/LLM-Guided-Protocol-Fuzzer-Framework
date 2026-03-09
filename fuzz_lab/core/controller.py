"""
TargetController — Docker-based target lifecycle management.

Handles building instrumented (GCOV-enabled) Docker images, starting/stopping
containers, crash recovery, health checks, and state cleanup for stateful
protocols (e.g. wiping /var/lib/mosquitto for MQTT).
"""

from __future__ import annotations

import logging
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

import psutil

from fuzz_lab.config import DOCKER_CONFIG, TargetSpec

logger = logging.getLogger(__name__)


class TargetController:
    """Manage the lifecycle of a single fuzzable Docker target."""

    def __init__(self, target: TargetSpec, workspace: str | Path = ".") -> None:
        self.target = target
        self.workspace = Path(workspace)
        self.container_id: Optional[str] = None
        self._gcov_volume = self.workspace / "gcov_data" / target.name
        self._gcov_volume.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build_target(self) -> None:
        """Build the Docker image with GCOV instrumentation flags."""
        build_ctx = self.workspace / self.target.docker_build_context
        if not build_ctx.exists():
            raise FileNotFoundError(
                f"Docker build context not found: {build_ctx}"
            )

        cmd = [
            "docker", "build",
            "--build-arg", f"CFLAGS={self.target.compile_flags}",
            "--build-arg", f"CXXFLAGS={self.target.compile_flags}",
            "-t", self.target.docker_image,
            str(build_ctx),
        ]
        logger.info("Building image %s from %s", self.target.docker_image, build_ctx)
        subprocess.run(cmd, check=True, timeout=600)
        logger.info("Image built: %s", self.target.docker_image)

    # ------------------------------------------------------------------
    # Container Lifecycle
    # ------------------------------------------------------------------

    def start_container(self) -> str:
        """Start a new container and return its ID.

        Mount configuration uses VirtioFS on macOS (Docker Desktop routes
        bind mounts through VirtioFS automatically).  The consistency hint
        is included for clarity but is a no-op on VirtioFS.
        """
        cfg = DOCKER_CONFIG
        consistency = cfg.get("mount_consistency", "consistent")

        # Primary mount: GCOV output directory
        gcov_mount = (
            f"type=bind,"
            f"source={self._gcov_volume.resolve()},"
            f"target={self.target.gcov_prefix},"
            f"consistency={consistency}"
        )

        cmd = [
            "docker", "run", "-d",
            "--name", f"fuzzlab_{self.target.name}",
            "--network", cfg["network_name"],
            "--memory", cfg["container_memory_limit"],
            "--cpus", str(cfg["container_cpu_count"]),
            "-p", f"{self.target.default_port}:{self.target.default_port}/udp",
            "-p", f"{self.target.default_port}:{self.target.default_port}/tcp",
            "--mount", gcov_mount,
            self.target.docker_image,
        ]
        logger.info("Starting container for %s", self.target.name)
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        self.container_id = result.stdout.strip()[:12]
        logger.info("Container started: %s", self.container_id)

        # Wait for the target port to become available
        self._wait_for_port()
        return self.container_id

    def stop_container(self) -> None:
        """Stop and remove the container."""
        if not self.container_id:
            return
        logger.info("Stopping container %s", self.container_id)
        subprocess.run(
            ["docker", "rm", "-f", self.container_id],
            capture_output=True, timeout=30,
        )
        self.container_id = None

    def restart_on_crash(self) -> str:
        """Handle a crash: log it, clean state dirs, restart the container."""
        logger.warning("Crash detected — restarting %s", self.target.name)

        # Clean state directories for stateful protocols
        if self.target.stateful and self.container_id:
            for d in self.target.clean_dirs:
                subprocess.run(
                    ["docker", "exec", self.container_id, "sh", "-c",
                     f"rm -rf {d}/* 2>/dev/null || true"],
                    capture_output=True, timeout=10,
                )

        # Remove the crashed container
        self.stop_container()

        # Cooldown before restart
        time.sleep(DOCKER_CONFIG["restart_cooldown_sec"])

        return self.start_container()

    # ------------------------------------------------------------------
    # Health Checking
    # ------------------------------------------------------------------

    def get_health(self) -> bool:
        """Check if the target is alive: container running + port open."""
        if not self.container_id:
            return False

        # Check container is running
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.container_id],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0 or result.stdout.strip() != "true":
            return False

        # Check port is reachable
        return self._check_port()

    def _check_port(self) -> bool:
        try:
            with socket.create_connection(
                ("127.0.0.1", self.target.default_port), timeout=2
            ):
                return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            return False

    def _wait_for_port(self) -> None:
        cfg = DOCKER_CONFIG
        for attempt in range(cfg["health_check_retries"]):
            if self._check_port():
                logger.debug("Port %d is up", self.target.default_port)
                return
            time.sleep(cfg["health_check_interval_sec"])
        logger.warning(
            "Port %d not reachable after %d attempts",
            self.target.default_port, cfg["health_check_retries"],
        )
