"""
seed_gen — Generate initial seed corpora for DNS and MQTT fuzzing.

Produces a small set of high-quality, protocol-valid packets that Boofuzz
loads into its initial mutation queue.  Good seeds accelerate coverage
exploration by starting from structurally correct packets.

Usage:
    python -m fuzz_lab.utils.seed_gen [--protocol dns|mqtt|all] [--output-dir fuzz_lab/corpus]

Dependencies:
    scapy — for DNS packet construction (pip install scapy)
    struct — for MQTT packet construction (stdlib)
"""

from __future__ import annotations

import argparse
import logging
import struct
import sys
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DNS Seed Generation (using scapy)
# ---------------------------------------------------------------------------

def generate_dns_seeds() -> List[Tuple[str, bytes]]:
    """Generate valid DNS query packets as raw bytes.

    Returns a list of (description, raw_bytes) tuples.
    Falls back to manual construction if scapy is unavailable.
    """
    seeds: List[Tuple[str, bytes]] = []

    try:
        from scapy.all import DNS, DNSQR, raw as scapy_raw
        seeds.extend(_dns_seeds_scapy(DNS, DNSQR, scapy_raw))
    except ImportError:
        logger.warning("scapy not installed — generating DNS seeds manually")
        seeds.extend(_dns_seeds_manual())

    return seeds


def _dns_seeds_scapy(DNS, DNSQR, scapy_raw) -> List[Tuple[str, bytes]]:
    """Generate DNS seeds using scapy for correctness."""
    seeds = []

    # Standard A query
    pkt = DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A", qclass="IN"))
    seeds.append(("dns_a_query_example_com", bytes(scapy_raw(pkt))))

    # AAAA query
    pkt = DNS(id=0x2345, rd=1, qd=DNSQR(qname="example.com", qtype="AAAA", qclass="IN"))
    seeds.append(("dns_aaaa_query_example_com", bytes(scapy_raw(pkt))))

    # TXT query
    pkt = DNS(id=0x3456, rd=1, qd=DNSQR(qname="example.com", qtype="TXT", qclass="IN"))
    seeds.append(("dns_txt_query_example_com", bytes(scapy_raw(pkt))))

    # MX query
    pkt = DNS(id=0x4567, rd=1, qd=DNSQR(qname="example.com", qtype="MX", qclass="IN"))
    seeds.append(("dns_mx_query_example_com", bytes(scapy_raw(pkt))))

    # NS query for root
    pkt = DNS(id=0x5678, rd=1, qd=DNSQR(qname=".", qtype="NS", qclass="IN"))
    seeds.append(("dns_ns_query_root", bytes(scapy_raw(pkt))))

    # SOA query
    pkt = DNS(id=0x6789, rd=1, qd=DNSQR(qname="example.com", qtype="SOA", qclass="IN"))
    seeds.append(("dns_soa_query_example_com", bytes(scapy_raw(pkt))))

    # ANY query (often triggers interesting code paths)
    pkt = DNS(id=0x789a, rd=1, qd=DNSQR(qname="example.com", qtype="ANY", qclass="IN"))
    seeds.append(("dns_any_query_example_com", bytes(scapy_raw(pkt))))

    # Long subdomain (boundary testing)
    long_name = "a" * 63 + ".example.com"
    pkt = DNS(id=0x89ab, rd=1, qd=DNSQR(qname=long_name, qtype="A", qclass="IN"))
    seeds.append(("dns_a_query_long_label", bytes(scapy_raw(pkt))))

    return seeds


def _dns_seeds_manual() -> List[Tuple[str, bytes]]:
    """Construct DNS packets manually (no scapy dependency)."""
    seeds = []

    def _encode_name(name: str) -> bytes:
        """Encode a DNS name into wire format."""
        parts = name.rstrip(".").split(".")
        result = b""
        for part in parts:
            result += bytes([len(part)]) + part.encode()
        result += b"\x00"
        return result

    def _dns_query(txn_id: int, name: str, qtype: int) -> bytes:
        header = struct.pack(
            "!HHHHHH",
            txn_id,    # Transaction ID
            0x0100,    # Flags: standard query, RD=1
            1,         # QDCOUNT
            0, 0, 0,   # ANCOUNT, NSCOUNT, ARCOUNT
        )
        question = _encode_name(name) + struct.pack("!HH", qtype, 1)  # qclass=IN
        return header + question

    # A=1, AAAA=28, TXT=16, MX=15, NS=2, SOA=6, ANY=255
    seeds.append(("dns_a_query_example_com", _dns_query(0x1234, "example.com", 1)))
    seeds.append(("dns_aaaa_query_example_com", _dns_query(0x2345, "example.com", 28)))
    seeds.append(("dns_txt_query_example_com", _dns_query(0x3456, "example.com", 16)))
    seeds.append(("dns_mx_query_example_com", _dns_query(0x4567, "example.com", 15)))
    seeds.append(("dns_ns_query_root", _dns_query(0x5678, ".", 2)))
    seeds.append(("dns_soa_query_example_com", _dns_query(0x6789, "example.com", 6)))
    seeds.append(("dns_any_query_example_com", _dns_query(0x789a, "example.com", 255)))

    # Long label
    long_name = "a" * 63 + ".example.com"
    seeds.append(("dns_a_query_long_label", _dns_query(0x89ab, long_name, 1)))

    return seeds


# ---------------------------------------------------------------------------
# MQTT Seed Generation
# ---------------------------------------------------------------------------

def generate_mqtt_seeds() -> List[Tuple[str, bytes]]:
    """Generate valid MQTT v3.1.1 packets as raw bytes.

    Returns a list of (description, raw_bytes) tuples.
    """
    seeds = []

    # -- CONNECT ---------------------------------------------------------------
    seeds.append(("mqtt_connect_clean", _mqtt_connect("fuzz01", clean_session=True)))
    seeds.append(("mqtt_connect_persistent", _mqtt_connect("fuzz02", clean_session=False)))
    seeds.append(("mqtt_connect_with_will", _mqtt_connect(
        "fuzz03", clean_session=True,
        will_topic="will/topic", will_message=b"client died",
    )))
    seeds.append(("mqtt_connect_long_clientid", _mqtt_connect("A" * 23, clean_session=True)))

    # -- SUBSCRIBE -------------------------------------------------------------
    seeds.append(("mqtt_subscribe_single", _mqtt_subscribe(1, [("test/topic", 0)])))
    seeds.append(("mqtt_subscribe_wildcard_plus", _mqtt_subscribe(2, [("sensor/+/data", 1)])))
    seeds.append(("mqtt_subscribe_wildcard_hash", _mqtt_subscribe(3, [("#", 2)])))
    seeds.append(("mqtt_subscribe_multi", _mqtt_subscribe(4, [
        ("topic/a", 0), ("topic/b", 1), ("topic/c", 2),
    ])))

    # -- PUBLISH ---------------------------------------------------------------
    seeds.append(("mqtt_publish_qos0", _mqtt_publish("test/topic", b"hello", qos=0)))
    seeds.append(("mqtt_publish_qos1", _mqtt_publish("test/topic", b"hello", qos=1, pkt_id=1)))
    seeds.append(("mqtt_publish_retain", _mqtt_publish(
        "test/retained", b"persistent", qos=0, retain=True,
    )))
    seeds.append(("mqtt_publish_empty", _mqtt_publish("test/empty", b"", qos=0)))
    seeds.append(("mqtt_publish_large", _mqtt_publish(
        "test/large", b"X" * 1024, qos=0,
    )))

    # -- PINGREQ ---------------------------------------------------------------
    seeds.append(("mqtt_pingreq", bytes([0xC0, 0x00])))

    # -- DISCONNECT ------------------------------------------------------------
    seeds.append(("mqtt_disconnect", bytes([0xE0, 0x00])))

    return seeds


def _encode_remaining_length(length: int) -> bytes:
    """Encode MQTT remaining length (variable-length encoding)."""
    out = bytearray()
    while True:
        encoded_byte = length % 128
        length //= 128
        if length > 0:
            encoded_byte |= 0x80
        out.append(encoded_byte)
        if length == 0:
            break
    return bytes(out)


def _encode_utf8_string(s: str) -> bytes:
    """Encode a string as MQTT UTF-8 (2-byte length prefix + data)."""
    encoded = s.encode("utf-8")
    return struct.pack("!H", len(encoded)) + encoded


def _mqtt_connect(
    client_id: str,
    clean_session: bool = True,
    keep_alive: int = 60,
    will_topic: str = "",
    will_message: bytes = b"",
) -> bytes:
    """Build an MQTT v3.1.1 CONNECT packet."""
    # Variable header
    var_header = b""
    var_header += _encode_utf8_string("MQTT")  # Protocol name
    var_header += bytes([4])  # Protocol level (4 = v3.1.1)

    # Connect flags
    flags = 0
    if clean_session:
        flags |= 0x02
    if will_topic:
        flags |= 0x04  # Will flag
        flags |= (0 << 3)  # Will QoS = 0
    var_header += bytes([flags])
    var_header += struct.pack("!H", keep_alive)

    # Payload
    payload = _encode_utf8_string(client_id)
    if will_topic:
        payload += _encode_utf8_string(will_topic)
        payload += struct.pack("!H", len(will_message)) + will_message

    remaining = var_header + payload
    packet = bytes([0x10]) + _encode_remaining_length(len(remaining)) + remaining
    return packet


def _mqtt_subscribe(packet_id: int, topics: list) -> bytes:
    """Build an MQTT SUBSCRIBE packet.

    topics: list of (topic_filter, qos) tuples.
    """
    var_header = struct.pack("!H", packet_id)
    payload = b""
    for topic, qos in topics:
        payload += _encode_utf8_string(topic)
        payload += bytes([qos])

    remaining = var_header + payload
    packet = bytes([0x82]) + _encode_remaining_length(len(remaining)) + remaining
    return packet


def _mqtt_publish(
    topic: str,
    payload_data: bytes,
    qos: int = 0,
    retain: bool = False,
    pkt_id: int | None = None,
) -> bytes:
    """Build an MQTT PUBLISH packet."""
    # Fixed header byte
    fixed_byte = 0x30
    fixed_byte |= (qos & 0x03) << 1
    if retain:
        fixed_byte |= 0x01

    var_header = _encode_utf8_string(topic)
    if qos > 0 and pkt_id is not None:
        var_header += struct.pack("!H", pkt_id)

    remaining = var_header + payload_data
    packet = bytes([fixed_byte]) + _encode_remaining_length(len(remaining)) + remaining
    return packet


# ---------------------------------------------------------------------------
# Corpus Writer
# ---------------------------------------------------------------------------

def write_corpus(
    seeds: List[Tuple[str, bytes]],
    output_dir: Path,
    protocol: str,
) -> int:
    """Write seed files to the corpus directory.

    Each seed is written as a binary file named {protocol}_{description}.bin.
    Returns the number of seeds written.
    """
    proto_dir = output_dir / protocol
    proto_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for name, data in seeds:
        seed_path = proto_dir / f"{name}.bin"
        seed_path.write_bytes(data)
        count += 1
        logger.debug("Wrote seed: %s (%d bytes)", seed_path, len(data))

    logger.info("Wrote %d %s seeds to %s", count, protocol.upper(), proto_dir)
    return count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate initial seed corpus for protocol fuzzing",
    )
    parser.add_argument(
        "--protocol", "-p",
        choices=["dns", "mqtt", "all"],
        default="all",
        help="Protocol to generate seeds for",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="fuzz_lab/corpus",
        help="Output directory for seed files",
    )

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    output_dir = Path(args.output_dir)
    total = 0

    if args.protocol in ("dns", "all"):
        dns_seeds = generate_dns_seeds()
        total += write_corpus(dns_seeds, output_dir, "dns")

    if args.protocol in ("mqtt", "all"):
        mqtt_seeds = generate_mqtt_seeds()
        total += write_corpus(mqtt_seeds, output_dir, "mqtt")

    print(f"\nGenerated {total} seed files in {output_dir}/")


if __name__ == "__main__":
    main()
