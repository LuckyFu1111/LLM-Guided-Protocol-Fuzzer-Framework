"""
sync_source — Clone target source trees to the host for PathRemapper.

The GCOV/LCOV path remapping in monitor.py requires that the host-side
file tree mirrors the container-side source layout.  This script clones
the exact versions of BIND9 and Mosquitto (as defined in config.py) into
targets/<name>/src/ so that lcov and genhtml can resolve source paths.

Usage:
    python -m fuzz_lab.utils.sync_source [--target bind9|mosquitto|all] [--workspace .]

The script is idempotent — if the source tree already exists at the
correct version, it skips the clone.
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

from fuzz_lab.config import TARGET_CONFIG, TargetSpec

logger = logging.getLogger(__name__)

# Version tags matching what the Dockerfiles pin to.
# These must stay in sync with the ARG lines in each Dockerfile.
TARGET_VERSIONS = {
    "bind9": "v9_18_15",
    "mosquitto": "v2.0.15",
}


def sync_target_source(
    target_name: str,
    workspace: Path,
    force: bool = False,
) -> Path:
    """Clone (or update) a target's source tree to the host.

    Parameters
    ----------
    target_name : str
        Key in TARGET_CONFIG (e.g. "bind9", "mosquitto").
    workspace : Path
        Root workspace directory (contains targets/).
    force : bool
        If True, delete existing source dir and re-clone.

    Returns
    -------
    Path
        The local source directory.
    """
    if target_name not in TARGET_CONFIG:
        raise ValueError(f"Unknown target: {target_name}")

    spec: TargetSpec = TARGET_CONFIG[target_name]
    version_tag = TARGET_VERSIONS.get(target_name)
    if not version_tag:
        raise ValueError(f"No version tag defined for target: {target_name}")

    # Source directory: workspace / targets / <name> / src
    source_dir = workspace / spec.source_dir_host
    if not source_dir.is_absolute():
        source_dir = workspace / source_dir

    # Check if already cloned at the right version
    if source_dir.exists() and not force:
        if _check_version(source_dir, version_tag):
            logger.info(
                "[%s] Source already at %s in %s — skipping",
                target_name, version_tag, source_dir,
            )
            return source_dir
        logger.info(
            "[%s] Source exists but version mismatch — re-cloning",
            target_name,
        )
        _remove_dir(source_dir)

    # Clone
    source_dir.parent.mkdir(parents=True, exist_ok=True)
    logger.info(
        "[%s] Cloning %s (tag: %s) into %s",
        target_name, spec.source_repo, version_tag, source_dir,
    )

    cmd = [
        "git", "clone",
        "--depth", "1",
        "--branch", version_tag,
        spec.source_repo,
        str(source_dir),
    ]

    try:
        subprocess.run(
            cmd, check=True, capture_output=True, text=True, timeout=300,
        )
    except subprocess.CalledProcessError as exc:
        logger.error(
            "[%s] git clone failed (rc=%d):\n%s",
            target_name, exc.returncode, exc.stderr,
        )
        raise
    except subprocess.TimeoutExpired:
        logger.error("[%s] git clone timed out after 300s", target_name)
        raise

    # Verify
    if _check_version(source_dir, version_tag):
        logger.info("[%s] Source synced successfully at %s", target_name, version_tag)
    else:
        logger.warning("[%s] Source cloned but version tag mismatch", target_name)

    return source_dir


def _check_version(source_dir: Path, expected_tag: str) -> bool:
    """Check if a git repo is at the expected tag/branch."""
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"],
            cwd=str(source_dir),
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip() == expected_tag

        # Fallback: check branch name
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(source_dir),
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() == expected_tag
    except (subprocess.SubprocessError, OSError):
        return False


def _remove_dir(path: Path) -> None:
    """Remove a directory tree."""
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def verify_path_mapping(target_name: str, workspace: Path) -> bool:
    """Verify that the host source tree matches the container layout.

    Checks that key files referenced in the CVE catalog exist on the host.
    """
    spec = TARGET_CONFIG[target_name]
    source_dir = workspace / spec.source_dir_host

    if not source_dir.exists():
        logger.error("[%s] Source directory does not exist: %s", target_name, source_dir)
        return False

    # Check a sample of affected_component paths from CVE catalog
    missing = []
    for cve in spec.cves:
        if not cve.affected_component or "/" not in cve.affected_component:
            continue
        component_path = source_dir / cve.affected_component
        if not component_path.exists():
            missing.append(cve.affected_component)

    if missing:
        logger.warning(
            "[%s] %d CVE component paths not found on host:\n  %s",
            target_name, len(missing), "\n  ".join(missing),
        )
        return False

    logger.info("[%s] All CVE component paths verified on host", target_name)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync target source trees to host for GCOV path remapping",
    )
    parser.add_argument(
        "--target", "-t",
        choices=list(TARGET_CONFIG.keys()) + ["all"],
        default="all",
        help="Target to sync (default: all)",
    )
    parser.add_argument(
        "--workspace", "-w",
        type=str,
        default=".",
        help="Workspace root directory",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-clone even if source exists",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify path mapping after sync",
    )

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    workspace = Path(args.workspace)
    targets = list(TARGET_CONFIG.keys()) if args.target == "all" else [args.target]

    for target_name in targets:
        try:
            source_dir = sync_target_source(target_name, workspace, force=args.force)
            print(f"  [{target_name}] Source at: {source_dir}")

            if args.verify:
                ok = verify_path_mapping(target_name, workspace)
                status = "OK" if ok else "INCOMPLETE"
                print(f"  [{target_name}] Path mapping: {status}")

        except Exception as exc:
            print(f"  [{target_name}] FAILED: {exc}", file=sys.stderr)
            continue

    print("\nDone.")


if __name__ == "__main__":
    main()
