#!/bin/bash
# =============================================================================
# Mosquitto Fuzzing Entrypoint
# =============================================================================
# Responsibilities:
#   1. Ensure the GCOV output directory is writable.
#   2. Start mosquitto in the foreground as PID 1.
#   3. Handle SIGUSR1 to flush gcov data (__gcov_flush).
# =============================================================================

set -euo pipefail

GCOV_OUT="${GCOV_PREFIX:-/usr/local/mosquitto/gcov_out}"

# Ensure gcov output directory exists and is writable.
mkdir -p "${GCOV_OUT}"
chmod -R 777 "${GCOV_OUT}" 2>/dev/null || true

# Verify .gcno files from the build tree
MOSQUITTO_SRC="/usr/src/mosquitto"
GCNO_COUNT=$(find "${MOSQUITTO_SRC}" -name '*.gcno' 2>/dev/null | head -20 | wc -l)
echo "[entrypoint] Found ${GCNO_COUNT}+ .gcno files in ${MOSQUITTO_SRC}"

if [ "${GCNO_COUNT}" -eq 0 ]; then
    echo "[entrypoint] WARNING: No .gcno files found. GCOV coverage will not work."
    echo "[entrypoint] Ensure the image was built with --coverage flags."
fi

# Validate mosquitto binary
if ! mosquitto -h > /dev/null 2>&1; then
    echo "[entrypoint] ERROR: mosquitto binary not functional"
    exit 1
fi

# Create persistence directory
mkdir -p /var/lib/mosquitto
chmod 777 /var/lib/mosquitto 2>/dev/null || true

echo "[entrypoint] Starting mosquitto (GCOV_PREFIX=${GCOV_OUT})"
echo "[entrypoint] Config: /etc/mosquitto/mosquitto.conf"
echo "[entrypoint] Send SIGUSR1 to PID 1 to flush gcov counters"

# Run mosquitto in foreground as PID 1
# -c = config file, -v = verbose
exec mosquitto -c /etc/mosquitto/mosquitto.conf -v
