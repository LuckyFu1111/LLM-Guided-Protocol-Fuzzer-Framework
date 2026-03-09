# =============================================================================
# Mosquitto GCOV-Instrumented Build for Fuzzing
# =============================================================================
# Targets: CVE-2021-34430 (NULL pointer deref on invalid PUBLISH) as the base,
#          plus all other Mosquitto CVEs in the catalog.
#
# Compiles Eclipse Mosquitto from source with full GCOV instrumentation.
# Coverage data (.gcda) written to a volume-mounted path for host-side analysis.
#
# Build:
#   docker build -t fuzzlab/mosquitto-gcov:latest targets/mosquitto/
#
# Run:
#   docker run -d -p 1883:1883 \
#     -v $(pwd)/gcov_data/mosquitto:/usr/local/mosquitto/gcov_out \
#     --name fuzzlab_mosquitto fuzzlab/mosquitto-gcov:latest
# =============================================================================

FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# ---- Build dependencies -----------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libssl-dev \
        libcjson-dev \
        libwebsockets-dev \
        xsltproc \
        docbook-xsl \
        lcov \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- Mosquitto source -------------------------------------------------------
# Pin to 2.0.15 — last release before CVE-2021-34430 was fully patched.
# The NULL pointer deref in handle_publish.c is present in this version.
ARG MOSQUITTO_VERSION=v2.0.15
ARG MOSQUITTO_SRC=/usr/src/mosquitto

RUN git clone --depth 1 --branch ${MOSQUITTO_VERSION} \
        https://github.com/eclipse-mosquitto/mosquitto.git ${MOSQUITTO_SRC}

WORKDIR ${MOSQUITTO_SRC}

# ---- Instrumented build ------------------------------------------------------
ARG CFLAGS="-g -O0 --coverage -fprofile-arcs -ftest-coverage"
ARG CXXFLAGS="-g -O0 --coverage -fprofile-arcs -ftest-coverage"
ARG LDFLAGS="--coverage"

# GCOV_PREFIX routes .gcda output to the mounted volume
ENV GCOV_PREFIX=/usr/local/mosquitto/gcov_out
ENV GCOV_PREFIX_STRIP=0

# Mosquitto uses make (not cmake for the broker itself in older versions).
# We pass coverage flags directly.
RUN make -j"$(nproc)" \
        WITH_TLS=yes \
        WITH_CJSON=yes \
        WITH_WEBSOCKETS=no \
        WITH_DOCS=no \
        WITH_PLUGINS=yes \
        CFLAGS="${CFLAGS}" \
        LDFLAGS="${LDFLAGS}" \
    && make install DESTDIR=/opt/mosquitto-install prefix=/usr/local/mosquitto

# ---- Runtime image -----------------------------------------------------------
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libcjson1 \
        lcov \
        procps \
        gdb \
    && rm -rf /var/lib/apt/lists/*

# Copy the full build tree (includes .gcno files for lcov)
COPY --from=builder /usr/src/mosquitto /usr/src/mosquitto

# Copy installed Mosquitto binaries and libs
COPY --from=builder /opt/mosquitto-install/usr/local/mosquitto /usr/local/mosquitto

# Ensure mosquitto binary is on PATH
ENV PATH="/usr/local/mosquitto/sbin:/usr/local/mosquitto/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/mosquitto/lib:${LD_LIBRARY_PATH}"

# Create gcov output directory (volume-mounted at runtime)
RUN mkdir -p /usr/local/mosquitto/gcov_out

# Carry over GCOV env
ENV GCOV_PREFIX=/usr/local/mosquitto/gcov_out
ENV GCOV_PREFIX_STRIP=0

# Create runtime directories
RUN mkdir -p /var/lib/mosquitto /var/log/mosquitto /etc/mosquitto

# ---- Mosquitto config for fuzzing -------------------------------------------
# No authentication, verbose logging, aggressive limits for fuzzing.
COPY mosquitto.conf /etc/mosquitto/mosquitto.conf

# Expose MQTT port
EXPOSE 1883

# Copy and set entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
