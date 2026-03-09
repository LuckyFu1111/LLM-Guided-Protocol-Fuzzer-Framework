# =============================================================================
# BIND9 GCOV-Instrumented Build for Fuzzing
# =============================================================================
# Targets: CVE-2023-2828 (cache memory exhaustion via specific RRset queries)
#          and all other BIND9 CVEs in the catalog.
#
# The image compiles BIND9 from source with full GCOV instrumentation so that
# every code path executed by the fuzzer is recorded.  Coverage data (.gcda)
# is written to a volume-mounted directory accessible from the host.
#
# Build:
#   docker build -t fuzzlab/bind9-gcov:latest targets/bind9/
#
# Run:
#   docker run -d -p 5353:53/udp -p 5353:53/tcp \
#     -v $(pwd)/gcov_data/bind9:/opt/bind9/gcov_out \
#     --name fuzzlab_bind9 fuzzlab/bind9-gcov:latest
# =============================================================================

FROM debian:bookworm-slim AS builder

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ---- Build dependencies -----------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        autoconf \
        automake \
        libtool \
        pkg-config \
        libssl-dev \
        libcap-dev \
        libuv1-dev \
        libnghttp2-dev \
        libjemalloc-dev \
        libxml2-dev \
        liblmdb-dev \
        python3 \
        python3-ply \
        lcov \
        git \
        ca-certificates \
        wget \
    && rm -rf /var/lib/apt/lists/*

# ---- BIND9 source -----------------------------------------------------------
# Pin to 9.18.15 — the last release vulnerable to CVE-2023-2828.
# The fix landed in 9.18.16.
ARG BIND9_VERSION=9_18_15
ARG BIND9_SRC=/usr/src/bind9

RUN git clone --depth 1 --branch v${BIND9_VERSION} \
        https://gitlab.isc.org/isc-projects/bind9.git ${BIND9_SRC}

WORKDIR ${BIND9_SRC}

# ---- Instrumented build ------------------------------------------------------
# CFLAGS/CXXFLAGS are passed via build-arg from TargetController.build_target()
# but we also set sensible defaults matching config.py.
ARG CFLAGS="-g -O0 --coverage -fprofile-arcs -ftest-coverage"
ARG CXXFLAGS="-g -O0 --coverage -fprofile-arcs -ftest-coverage"
ARG LDFLAGS="--coverage"

# Point .gcda output to a dedicated directory that we volume-mount at runtime.
# GCOV_PREFIX replaces the leading path so the .gcda files land under
# /opt/bind9/gcov_out/<original-path-structure>.
ENV GCOV_PREFIX=/opt/bind9/gcov_out
ENV GCOV_PREFIX_STRIP=0

RUN autoreconf -fi

RUN ./configure \
        --prefix=/opt/bind9 \
        --with-openssl \
        --enable-full-report \
        --disable-linux-caps \
        CFLAGS="${CFLAGS}" \
        CXXFLAGS="${CXXFLAGS}" \
        LDFLAGS="${LDFLAGS}"

# Build with parallelism.  The .gcno files (compile-time notes) are generated
# alongside each .o and stay in the build tree.
RUN make -j"$(nproc)"
RUN make install

# ---- Runtime image -----------------------------------------------------------
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libcap2 \
        libuv1 \
        libnghttp2-14 \
        libjemalloc2 \
        libxml2 \
        liblmdb0 \
        lcov \
        procps \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy the full build tree (includes .gcno files needed by lcov)
COPY --from=builder /usr/src/bind9 /usr/src/bind9

# Copy the installed BIND9 binaries
COPY --from=builder /opt/bind9 /opt/bind9

# Create the gcov output directory — will be volume-mounted at runtime
RUN mkdir -p /opt/bind9/gcov_out

# Carry over the GCOV env so named writes .gcda to the mounted volume
ENV GCOV_PREFIX=/opt/bind9/gcov_out
ENV GCOV_PREFIX_STRIP=0

# Create required runtime directories
RUN mkdir -p /var/cache/bind /var/run/named /etc/bind

# ---- Minimal named.conf for fuzzing -----------------------------------------
# Recursive resolver config — required to exercise the cache path that
# CVE-2023-2828 targets.
RUN cat > /etc/bind/named.conf <<'NAMEDCONF'
options {
    directory "/var/cache/bind";
    listen-on port 53 { any; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion yes;
    allow-recursion { any; };
    dnssec-validation no;
    # Limits tuned for fuzzing — keep memory bounded
    max-cache-size 64M;
    recursive-clients 100;
    # Disable rate limiting so fuzz packets aren't dropped
    rate-limit { responses-per-second 0; };
};

zone "." IN {
    type hint;
    file "/etc/bind/db.root";
};

logging {
    channel fuzz_log {
        stderr;
        severity debug 1;
        print-time yes;
        print-category yes;
    };
    category default { fuzz_log; };
};
NAMEDCONF

# Minimal root hints so named can start
RUN cat > /etc/bind/db.root <<'DBROOT'
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
DBROOT

# Expose DNS ports
EXPOSE 53/udp
EXPOSE 53/tcp

# Copy and set entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
