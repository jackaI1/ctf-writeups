"""Read a packet capture (.pcap) and list conversations, follow streams and search payloads.

A capture file records network packets, such as those saved by Wireshark or
``tcpdump -w``. Many CTF network challenges hide a flag in one TCP stream, or in
data sent by one host. Opening Wireshark for each one is slow, and it is hard to
script. This module reads the classic pcap format with the standard library
only, so it runs anywhere Python does.

Supported: classic libpcap files (microsecond and nanosecond timestamps, either
byte order), Ethernet frames, IPv4, TCP and UDP. pcapng files are rejected with a
clear message. IPv6 and other protocols are counted but not decoded.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# magic number -> (struct byte order, timestamp fraction units per second)
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),  # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big-endian, nanoseconds
}
_ETHERNET = 1
_MAX_RECORD = 262_144  # libpcap's default snap length; larger records are corrupt


@dataclass(frozen=True)
class Packet:
    """A decoded IPv4 TCP or UDP packet."""

    number: int
    timestamp: float
    protocol: str  # "TCP" or "UDP"
    src: str
    sport: int
    dst: str
    dport: int
    seq: int  # TCP sequence number, 0 for UDP
    flags: int  # TCP flags byte, 0 for UDP
    payload: bytes

    @property
    def flow(self) -> tuple[str, str, str, int, str, int]:
        """Conversation key for one direction, e.g. ("TCP", "10.0.0.2", 4444, "10.0.0.9", 80)."""
        return self.protocol, self.src, self.sport, self.dst, self.dport

    def endpoint(self) -> str:
        return f"{self.src}:{self.sport}"


def iter_records(path: Path) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp, frame bytes) for each record in a classic pcap file."""
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise ValueError("file is too short to be a pcap")
        magic = header[:4]
        if magic not in _MAGIC:
            if magic == b"\x0a\x0d\x0d\x0a":
                raise ValueError("pcapng files are not supported; convert with editcap -F pcap")
            raise ValueError("not a classic pcap file")
        endian, units = _MAGIC[magic]
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype != _ETHERNET:
            raise ValueError(f"link type {linktype} is not Ethernet; only Ethernet captures are decoded")
        while True:
            record = handle.read(16)
            if not record:
                return
            if len(record) < 16:
                raise ValueError("capture ends in the middle of a record header")
            seconds, fraction, included, _original = struct.unpack(endian + "IIII", record)
            if included > _MAX_RECORD:
                raise ValueError(f"record of {included} bytes is larger than expected; file may be corrupt")
            frame = handle.read(included)
            if len(frame) < included:
                raise ValueError("capture ends in the middle of a packet")
            yield seconds + fraction / units, frame


def decode_frame(number: int, timestamp: float, frame: bytes) -> Packet | None:
    """Return a Packet for an Ethernet/IPv4/TCP-or-UDP frame, otherwise None."""
    if len(frame) < 14 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    segment = ip[ihl:]
    total_length = struct.unpack("!H", ip[2:4])[0]
    segment = segment[: max(0, total_length - ihl)] if total_length >= ihl else segment
    if proto == 6 and len(segment) >= 20:
        sport, dport, seq = struct.unpack("!HHI", segment[0:8])
        offset = (segment[12] >> 4) * 4
        flags = segment[13]
        return Packet(number, timestamp, "TCP", src, sport, dst, dport, seq, flags, segment[offset:])
    if proto == 17 and len(segment) >= 8:
        sport, dport, _length = struct.unpack("!HHH", segment[0:6])
        return Packet(number, timestamp, "UDP", src, sport, dst, dport, 0, 0, segment[8:])
    return None


def read_packets(path: Path) -> Iterator[Packet]:
    """Yield decoded IPv4 TCP and UDP packets, numbered from 1 like Wireshark."""
    for number, (timestamp, frame) in enumerate(iter_records(path), start=1):
        packet = decode_frame(number, timestamp, frame)
        if packet is not None:
            yield packet


def conversations(packets: list[Packet]) -> Counter[tuple[str, str, int, str, int]]:
    """Count packets per directed flow."""
    return Counter(p.flow for p in packets)


def follow_stream(packets: list[Packet], src: str, sport: int, dst: str, dport: int) -> bytes:
    """Rebuild one TCP direction's payload in sequence order.

    Retransmitted bytes are dropped when their sequence number was already
    seen. Gaps are not filled, so a missing packet shows up as a short stream.
    """
    chunks = [
        p
        for p in packets
        if p.protocol == "TCP" and p.src == src and p.sport == sport and p.dst == dst and p.dport == dport and p.payload
    ]
    if not chunks:
        return b""
    chunks.sort(key=lambda p: p.number)
    base = chunks[0].seq
    chunks.sort(key=lambda p: (p.seq - base) & 0xFFFFFFFF)
    out = bytearray()
    expected = None
    for packet in chunks:
        offset = (packet.seq - base) & 0xFFFFFFFF
        if expected is not None and offset + len(packet.payload) <= expected:
            continue  # fully retransmitted
        if expected is not None and offset < expected:
            packet_payload = packet.payload[expected - offset :]  # partial overlap
        else:
            packet_payload = packet.payload
        out += packet_payload
        expected = offset + len(packet.payload)
    return bytes(out)


def grep_payloads(packets: list[Packet], pattern: bytes) -> list[tuple[int, str, bytes]]:
    """Return (packet number, endpoint, matched text) for every payload match."""
    regex = re.compile(pattern)
    hits = []
    for packet in packets:
        for found in regex.finditer(packet.payload):
            hits.append((packet.number, packet.endpoint(), found.group(0)))
    return hits


def _printable(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List, follow and search packets in a pcap file.")
    parser.add_argument("capture", type=Path, help="classic .pcap file")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("summary", help="count packets per conversation")
    follow = commands.add_parser("follow", help="print one TCP direction's payload")
    follow.add_argument("--src", required=True, help="source address, e.g. 10.0.0.2")
    follow.add_argument("--sport", type=int, required=True)
    follow.add_argument("--dst", required=True)
    follow.add_argument("--dport", type=int, required=True)
    follow.add_argument("--raw", action="store_true", help="write the bytes unchanged instead of printable text")
    grep = commands.add_parser("grep", help="search every payload for a regular expression")
    grep.add_argument("pattern", help="regular expression, matched against raw bytes")
    grep.add_argument("--limit", type=int, default=50, help="maximum hits to print")
    args = parser.parse_args(argv)

    try:
        packets = list(read_packets(args.capture))
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.command == "summary":
        print(f"{len(packets)} TCP/UDP packets")
        for (proto, src, sport, dst, dport), count in conversations(packets).most_common():
            print(f"{count:6d}  {proto}  {src}:{sport} -> {dst}:{dport}")
        return 0

    if args.command == "follow":
        data = follow_stream(packets, args.src, args.sport, args.dst, args.dport)
        if args.raw:
            sys.stdout.buffer.write(data)
        else:
            print(_printable(data))
        return 0

    hits = grep_payloads(packets, args.pattern.encode())
    for number, endpoint, text in hits[: args.limit]:
        print(f"packet {number} from {endpoint}: {_printable(text)}")
    print(f"{len(hits)} hit(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
