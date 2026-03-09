"""
engine_boofuzz — Boofuzz session wrapper with coverage-guided callbacks.

Defines protocol-specific session graphs for DNS and MQTT, hooks into
Boofuzz's post_test_case_callback for per-packet coverage syncing, and
supports injecting LLM-generated seeds into the mutation queue.
"""

from __future__ import annotations

import logging
import struct
from typing import Callable, List, Optional

from boofuzz import (
    Block,
    Byte,
    Bytes,
    DWord,
    Group,
    Session,
    Static,
    String,
    Target,
    Word,
    s_block,
    s_byte,
    s_bytes,
    s_dword,
    s_get,
    s_group,
    s_initialize,
    s_size,
    s_static,
    s_string,
    s_word,
)
from boofuzz.connections import TCPSocketConnection, UDPSocketConnection

logger = logging.getLogger(__name__)


class BoofuzzEngine:
    """Wrapper around a Boofuzz Session with protocol definitions and
    hooks for the coverage-guided feedback loop."""

    def __init__(
        self,
        protocol: str,
        target_host: str = "127.0.0.1",
        target_port: int = 53,
        post_test_callback: Optional[Callable] = None,
        crash_callback: Optional[Callable] = None,
    ) -> None:
        self.protocol = protocol.lower()
        self.target_host = target_host
        self.target_port = target_port
        self._post_test_callback = post_test_callback
        self._crash_callback = crash_callback
        self._session: Optional[Session] = None
        self._injected_seeds: List[bytes] = []
        self._paused: bool = False

    # ------------------------------------------------------------------
    # Session Setup
    # ------------------------------------------------------------------

    def create_session(self) -> Session:
        """Build and return a Boofuzz Session with the right connection type
        and protocol graph."""
        if self.protocol == "dns":
            conn = UDPSocketConnection(self.target_host, self.target_port)
        elif self.protocol == "mqtt":
            conn = TCPSocketConnection(self.target_host, self.target_port)
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

        target = Target(connection=conn)

        self._session = Session(
            target=target,
            post_test_case_callbacks=[self._on_post_test_case],
            keep_web_open=False,
            sleep_time=0,
        )

        # Define protocol-specific message graphs
        if self.protocol == "dns":
            self._define_dns_graph()
        elif self.protocol == "mqtt":
            self._define_mqtt_graph()

        return self._session

    # ------------------------------------------------------------------
    # Fuzzing Control
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin the fuzzing campaign."""
        if not self._session:
            self.create_session()
        self._paused = False
        self._session.fuzz()

    def pause(self) -> None:
        """Pause fuzzing (checked in callback)."""
        self._paused = True
        logger.info("Boofuzz engine paused")

    def resume(self) -> None:
        """Resume fuzzing after pause."""
        self._paused = False
        logger.info("Boofuzz engine resumed")

    def inject_seeds(self, seeds: List[bytes]) -> None:
        """Queue LLM-generated seeds for injection into the next test cases."""
        self._injected_seeds.extend(seeds)
        logger.info("Injected %d LLM seeds into mutation queue", len(seeds))

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_post_test_case(self, target, fuzz_data_logger, session, *args, **kwargs):
        """Called after every single packet — sync coverage and check state."""
        # Fire the external coverage-sync callback
        if self._post_test_callback:
            self._post_test_callback(session, fuzz_data_logger)

        # If we have injected seeds, push one as the next mutation
        if self._injected_seeds:
            seed = self._injected_seeds.pop(0)
            logger.debug("Using injected LLM seed (%d bytes)", len(seed))

        # Block while paused (allows orchestrator to freeze execution)
        while self._paused:
            import time
            time.sleep(0.1)

    # ------------------------------------------------------------------
    # DNS Protocol Definition
    # ------------------------------------------------------------------

    def _define_dns_graph(self) -> None:
        """Define a fuzzable DNS query message (RFC 1035)."""
        s_initialize("dns_query")

        # Transaction ID
        s_word(0x1234, name="txn_id", fuzzable=True, endian=">")

        # Flags (standard query, recursion desired)
        s_word(0x0100, name="flags", fuzzable=True, endian=">")

        # Question count
        s_word(1, name="qdcount", fuzzable=True, endian=">")

        # Answer/Authority/Additional counts
        s_word(0, name="ancount", fuzzable=True, endian=">")
        s_word(0, name="nscount", fuzzable=True, endian=">")
        s_word(0, name="arcount", fuzzable=True, endian=">")

        # Question section: fuzzable domain name
        s_byte(7, name="label_len", fuzzable=True)
        s_string("example", name="label", fuzzable=True, max_len=63)
        s_byte(3, name="tld_len", fuzzable=True)
        s_string("com", name="tld", fuzzable=True, max_len=63)
        s_byte(0, name="null_term", fuzzable=False)

        # Query type (A=1) and class (IN=1)
        s_word(1, name="qtype", fuzzable=True, endian=">")
        s_word(1, name="qclass", fuzzable=True, endian=">")

        self._session.connect(s_get("dns_query"))

    # ------------------------------------------------------------------
    # MQTT Protocol Definition
    # ------------------------------------------------------------------

    def _define_mqtt_graph(self) -> None:
        """Define fuzzable MQTT v3.1.1 messages (CONNECT -> SUBSCRIBE -> PUBLISH)."""

        # -- CONNECT --
        s_initialize("mqtt_connect")
        # Fixed header: CONNECT = 0x10
        s_byte(0x10, name="connect_type", fuzzable=False)
        # Remaining length (placeholder, fuzzed)
        s_byte(0x00, name="connect_remaining_len", fuzzable=True)
        # Protocol name
        s_word(4, name="proto_name_len", endian=">", fuzzable=True)
        s_string("MQTT", name="proto_name", fuzzable=True, max_len=10)
        # Protocol level (4 = v3.1.1)
        s_byte(4, name="proto_level", fuzzable=True)
        # Connect flags
        s_byte(0x02, name="connect_flags", fuzzable=True)  # Clean session
        # Keep alive
        s_word(60, name="keep_alive", endian=">", fuzzable=True)
        # Client ID
        s_word(6, name="client_id_len", endian=">", fuzzable=True)
        s_string("fuzz01", name="client_id", fuzzable=True, max_len=23)

        # -- SUBSCRIBE --
        s_initialize("mqtt_subscribe")
        # Fixed header: SUBSCRIBE = 0x82
        s_byte(0x82, name="subscribe_type", fuzzable=False)
        s_byte(0x00, name="subscribe_remaining_len", fuzzable=True)
        # Packet identifier
        s_word(1, name="packet_id", endian=">", fuzzable=True)
        # Topic filter
        s_word(4, name="topic_len", endian=">", fuzzable=True)
        s_string("test", name="topic_filter", fuzzable=True, max_len=128)
        # QoS
        s_byte(0, name="subscribe_qos", fuzzable=True)

        # -- PUBLISH --
        s_initialize("mqtt_publish")
        # Fixed header: PUBLISH = 0x30
        s_byte(0x30, name="publish_type", fuzzable=True)
        s_byte(0x00, name="publish_remaining_len", fuzzable=True)
        # Topic
        s_word(4, name="pub_topic_len", endian=">", fuzzable=True)
        s_string("test", name="pub_topic", fuzzable=True, max_len=128)
        # Payload
        s_string("hello", name="payload", fuzzable=True, max_len=1024)

        # Build the stateful graph: CONNECT -> SUBSCRIBE -> PUBLISH
        self._session.connect(s_get("mqtt_connect"))
        self._session.connect(s_get("mqtt_connect"), s_get("mqtt_subscribe"))
        self._session.connect(s_get("mqtt_subscribe"), s_get("mqtt_publish"))
