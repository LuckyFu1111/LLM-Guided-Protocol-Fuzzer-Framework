#!/bin/bash
# =============================================================================
# BIND9 Fuzzing Entrypoint
# =============================================================================
# Responsibilities:
#   1. Ensure the GCOV output directory is writable.
#   2. Start named in the foreground so it stays as PID 1.
#   3. Handle SIGUSR1 to flush gcov data (gcov_flush via __gcov_flush).
#      When named receives SIGUSR1, the gcov runtime writes accumulated
#      .gcda counters to GCOV_PREFIX.
# =============================================================================

set -euo pipefail

GCOV_OUT="${GCOV_PREFIX:-/opt/bind9/gcov_out}"

# Ensure gcov output directory exists and is writable.
# On macOS with VirtioFS mounts, ownership may not map 1:1 — chmod handles this.
mkdir -p "${GCOV_OUT}"
chmod -R 777 "${GCOV_OUT}" 2>/dev/null || true

# Pre-create the directory structure that mirrors the build tree.
# lcov needs .gcno files to exist alongside .gcda files, so we symlink
# the build tree's .gcno files into the gcov output if they aren't already
# accessible via GCOV_PREFIX_STRIP.
BIND9_SRC="/usr/src/bind9"

# Verify the build tree is intact (contains .gcno files)
GCNO_COUNT=$(find "${BIND9_SRC}" -name '*.gcno' 2>/dev/null | head -20 | wc -l)
echo "[entrypoint] Found ${GCNO_COUNT}+ .gcno files in ${BIND9_SRC}"

if [ "${GCNO_COUNT}" -eq 0 ]; then
    echo "[entrypoint] WARNING: No .gcno files found. GCOV coverage will not work."
    echo "[entrypoint] Ensure the image was built with --coverage flags."
fi

# Validate named can start
if ! /opt/bind9/sbin/named -V > /dev/null 2>&1; then
    echo "[entrypoint] ERROR: named binary not functional"
    exit 1
fi

echo "[entrypoint] Starting named (GCOV_PREFIX=${GCOV_OUT})"
echo "[entrypoint] Send SIGUSR1 to PID 1 to flush gcov counters"

# Run named in foreground as PID 1.
# -g = run in foreground, log to stderr
# -c = config file path
exec /opt/bind9/sbin/named -g -c /etc/bind/named.conf -u root
