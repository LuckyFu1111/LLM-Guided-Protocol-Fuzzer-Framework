"""
Configuration for the LLM-Guided Protocol Fuzzing Framework.

Contains CVE catalogs with difficulty weights, target build definitions,
Ollama/LLM hyperparameters, and coverage-guided feedback loop thresholds.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# CVE Descriptor
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CVEEntry:
    """Single CVE with a difficulty weight (1=shallow/easy, 10=deep logic)."""
    cve_id: str
    weight: int          # 1-10
    description: str = ""
    affected_component: str = ""


# ---------------------------------------------------------------------------
# Target Definitions
# ---------------------------------------------------------------------------
@dataclass
class TargetSpec:
    """Everything needed to build, instrument, and fuzz a single target."""
    name: str
    protocol: str                     # "dns" | "mqtt"
    stateful: bool
    docker_image: str
    docker_build_context: str         # relative to /targets
    source_repo: str
    default_port: int
    gcov_prefix: str                  # path inside container
    clean_dirs: List[str]             # dirs to wipe on crash restart
    cves: List[CVEEntry] = field(default_factory=list)
    compile_flags: str = ""           # extra CFLAGS for instrumented build
    rfc_references: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CVE Catalogs
# ---------------------------------------------------------------------------

BIND9_CVES: List[CVEEntry] = [
    CVEEntry(
        cve_id="CVE-2023-2828",
        weight=1,
        description="named cache memory exhaustion via specific RRset queries",
        affected_component="cache",
    ),
    CVEEntry(
        cve_id="CVE-2021-25216",
        weight=2,
        description="buffer overflow in GSSAPI negotiation (GSS-TSIG)",
        affected_component="lib/dns/gss_tsig.c",
    ),
    CVEEntry(
        cve_id="CVE-2023-2911",
        weight=3,
        description="named crash on recursive-clients soft quota via specific query patterns",
        affected_component="resolver",
    ),
    CVEEntry(
        cve_id="CVE-2025-40775",
        weight=4,
        description="assertion failure triggered by malformed DNS responses",
        affected_component="resolver",
    ),
    CVEEntry(
        cve_id="CVE-2024-0760",
        weight=5,
        description="flood of pipelined DNS-over-TCP queries destabilises named",
        affected_component="lib/isc/netmgr",
    ),
    CVEEntry(
        cve_id="CVE-2024-1737",
        weight=6,
        description="excessive resource usage when processing large delegations",
        affected_component="resolver",
    ),
    CVEEntry(
        cve_id="CVE-2025-8677",
        weight=7,
        description="malformed TSIG record processing leads to assertion failure",
        affected_component="lib/dns/tsig.c",
    ),
    CVEEntry(
        cve_id="CVE-2025-40778",
        weight=8,
        description="crafted zone file causes named abort during loading",
        affected_component="lib/dns/zone.c",
    ),
    CVEEntry(
        cve_id="CVE-2023-4408",
        weight=9,
        description="CPU-exhaustion parsing large DNS messages",
        affected_component="lib/dns/message.c",
    ),
    CVEEntry(
        cve_id="CVE-2025-40780",
        weight=10,
        description="complex query chain triggers deep recursion stack overflow",
        affected_component="resolver",
    ),
]

MOSQUITTO_CVES: List[CVEEntry] = [
    CVEEntry(
        cve_id="CVE-2021-34430",
        weight=1,
        description="NULL pointer deref on invalid PUBLISH in broker",
        affected_component="src/handle_publish.c",
    ),
    CVEEntry(
        cve_id="CVE-2023-28366",
        weight=2,
        description="memory leak via repeated CONNECT packets without DISCONNECT",
        affected_component="src/handle_connect.c",
    ),
    CVEEntry(
        cve_id="CVE-2024-27357",
        weight=3,
        description="out-of-bounds read in UTF-8 topic validation",
        affected_component="lib/util_topic.c",
    ),
    CVEEntry(
        cve_id="CVE-2025-65953",
        weight=4,
        description="heap buffer overflow in SUBSCRIBE packet handler",
        affected_component="src/handle_subscribe.c",
    ),
    CVEEntry(
        cve_id="CVE-2023-35945",
        weight=5,
        description="integer overflow in property length decoding",
        affected_component="lib/packet_datatypes.c",
    ),
    CVEEntry(
        cve_id="CVE-2025-66023",
        weight=6,
        description="use-after-free on client disconnect during QoS 2 flow",
        affected_component="src/handle_pubrel.c",
    ),
    CVEEntry(
        cve_id="CVE-2024-42503",
        weight=7,
        description="ACL bypass via crafted MQTT v5 topic alias",
        affected_component="src/security_default.c",
    ),
    CVEEntry(
        cve_id="CVE-2025-68699",
        weight=8,
        description="state machine confusion via interleaved AUTH / CONNECT",
        affected_component="src/handle_auth.c",
    ),
    CVEEntry(
        cve_id="CVE-2025-52136",
        weight=9,
        description="retained-message deduplication logic causes DoS under load",
        affected_component="src/retain.c",
    ),
    CVEEntry(
        cve_id="CVE-2025-9161",
        weight=10,
        description="chained session-takeover via will-message + shared subscription race",
        affected_component="src/handle_connect.c",
    ),
]


# ---------------------------------------------------------------------------
# Target Configurations
# ---------------------------------------------------------------------------

TARGET_CONFIG: Dict[str, TargetSpec] = {
    "bind9": TargetSpec(
        name="bind9",
        protocol="dns",
        stateful=False,
        docker_image="fuzzlab/bind9-gcov:latest",
        docker_build_context="targets/bind9",
        source_repo="https://gitlab.isc.org/isc-projects/bind9.git",
        default_port=53,
        gcov_prefix="/usr/local/bind9/gcov_out",
        clean_dirs=["/var/cache/bind"],
        cves=BIND9_CVES,
        compile_flags="-g -O0 --coverage -fprofile-arcs -ftest-coverage",
        rfc_references=["RFC 1035", "RFC 2136", "RFC 8490", "RFC 2845"],
    ),
    "mosquitto": TargetSpec(
        name="mosquitto",
        protocol="mqtt",
        stateful=True,
        docker_image="fuzzlab/mosquitto-gcov:latest",
        docker_build_context="targets/mosquitto",
        source_repo="https://github.com/eclipse-mosquitto/mosquitto.git",
        default_port=1883,
        gcov_prefix="/usr/local/mosquitto/gcov_out",
        clean_dirs=["/var/lib/mosquitto", "/tmp/mosquitto"],
        cves=MOSQUITTO_CVES,
        compile_flags="-g -O0 --coverage -fprofile-arcs -ftest-coverage",
        rfc_references=["MQTT v3.1.1 (OASIS)", "MQTT v5.0 (OASIS)"],
    ),
}


# ---------------------------------------------------------------------------
# Ollama / LLM Hyperparameters
# ---------------------------------------------------------------------------

OLLAMA_CONFIG = {
    "base_url": "http://localhost:11434",
    "model": "qwen3:8b",
    "temperature": 0.8,
    "top_p": 0.95,
    "num_predict": 512,           # max tokens per response
    "timeout_seconds": 30,
    "max_retries": 3,
    "batch_size": 8,              # seeds per LLM call
}


# ---------------------------------------------------------------------------
# Coverage-Guided Feedback Loop Thresholds
# ---------------------------------------------------------------------------

COVERAGE_CONFIG = {
    "stagnation_window": 500,       # iterations without new paths before LLM kicks in
    "min_path_gain_ratio": 0.01,    # minimum new-paths / total-paths per LLM batch
    "lcov_poll_interval_sec": 2,    # seconds between lcov data pulls
    "gcov_flush_command": "kill -USR1 1",  # signal PID 1 inside container to flush gcov
}


# ---------------------------------------------------------------------------
# Docker / Runtime
# ---------------------------------------------------------------------------

DOCKER_CONFIG = {
    "network_name": "fuzzlab_net",
    "mount_type": "bind",           # VirtioFS on macOS handled transparently
    "restart_cooldown_sec": 3,
    "health_check_retries": 5,
    "health_check_interval_sec": 1,
    "container_memory_limit": "2g",
    "container_cpu_count": 2,
}


# ---------------------------------------------------------------------------
# Experiment Defaults
# ---------------------------------------------------------------------------

EXPERIMENT_CONFIG = {
    "max_iterations": 100_000,
    "crash_log_dir": "fuzz_lab/crashes",
    "corpus_dir": "fuzz_lab/corpus",
    "metrics_output": "fuzz_lab/metrics/results.csv",
    "seed_archive_dir": "fuzz_lab/seeds",
    "log_level": "INFO",
}
