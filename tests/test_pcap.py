import socket
import struct

import pytest

from ctf_tools.pcap import follow_stream, grep_payloads, main, read_packets

CLIENT = "10.0.0.2"
SERVER = "10.0.0.9"


def tcp_frame(src, sport, dst, dport, seq, payload=b"", flags=0x18):
    ethernet = b"\x00" * 12 + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        0,
        0,
        64,
        6,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return ethernet + ip + tcp


def udp_frame(src, sport, dst, dport, payload):
    ethernet = b"\x00" * 12 + b"\x08\x00"
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst)
    )
    return ethernet + ip + udp


def write_pcap(path, frames, endian="<", nanoseconds=False):
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    parts = [struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)]
    for index, frame in enumerate(frames):
        parts.append(struct.pack(endian + "IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
        parts.append(frame)
    path.write_bytes(b"".join(parts))
    return path


@pytest.fixture
def capture(tmp_path):
    frames = [
        tcp_frame(CLIENT, 51000, SERVER, 9000, 1000, b"", flags=0x02),  # SYN, no payload
        tcp_frame(CLIENT, 51000, SERVER, 9000, 1000, b"FLAG{"),
        tcp_frame(CLIENT, 51000, SERVER, 9000, 1010, b"stream}"),  # arrives before the middle chunk
        tcp_frame(CLIENT, 51000, SERVER, 9000, 1005, b"pcap_"),
        tcp_frame(CLIENT, 51000, SERVER, 9000, 1000, b"FLAG{"),  # retransmission
        tcp_frame(SERVER, 9000, CLIENT, 51000, 5000, b"ack data FLAG{nope}"),
        udp_frame(CLIENT, 53000, SERVER, 53, b"dns query FLAG{udp}"),
    ]
    return write_pcap(tmp_path / "capture.pcap", frames)


def test_reads_tcp_and_udp_packets(capture):
    packets = list(read_packets(capture))
    assert [p.protocol for p in packets] == ["TCP"] * 5 + ["TCP"] + ["UDP"]
    assert packets[0].payload == b""
    assert packets[-1].payload == b"dns query FLAG{udp}"


def test_follow_stream_reorders_and_drops_retransmissions(capture):
    packets = list(read_packets(capture))
    assert follow_stream(packets, CLIENT, 51000, SERVER, 9000) == b"FLAG{pcap_stream}"


def test_reverse_direction_is_separate(capture):
    packets = list(read_packets(capture))
    assert follow_stream(packets, SERVER, 9000, CLIENT, 51000) == b"ack data FLAG{nope}"


def test_grep_finds_flags_in_every_payload(capture):
    packets = list(read_packets(capture))
    hits = grep_payloads(packets, rb"FLAG\{[^}]*\}")
    # The split "FLAG{" fragments have no closing brace in the same packet, so only two complete matches.
    assert [(number, text) for number, _endpoint, text in hits] == [
        (6, b"FLAG{nope}"),
        (7, b"FLAG{udp}"),
    ]


def test_big_endian_nanosecond_capture_is_read(tmp_path):
    frame = tcp_frame(CLIENT, 1, SERVER, 2, 1, b"hi")
    path = write_pcap(tmp_path / "be.pcap", [frame], endian=">", nanoseconds=True)
    packets = list(read_packets(path))
    assert len(packets) == 1
    assert packets[0].payload == b"hi"


def test_pcapng_is_rejected_with_a_clear_message(tmp_path, capsys):
    path = tmp_path / "file.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    assert main([str(path), "summary"]) == 2
    assert "pcapng" in capsys.readouterr().err


def test_cli_summary_and_follow(capture, capsys):
    assert main([str(capture), "summary"]) == 0
    summary = capsys.readouterr().out
    assert "TCP" in summary and "UDP" in summary

    assert main([str(capture), "follow", "--src", CLIENT, "--sport", "51000", "--dst", SERVER, "--dport", "9000"]) == 0
    assert "FLAG{pcap_stream}" in capsys.readouterr().out


def test_cli_grep_prints_hits_and_respects_limit(capture, capsys):
    assert main([str(capture), "grep", "FLAG"]) == 0
    out = capsys.readouterr().out
    assert "packet 2 from 10.0.0.2:51000: FLAG" in out
    assert out.strip().endswith("4 hit(s)")

    assert main([str(capture), "grep", "FLAG", "--limit", "1"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2  # one hit line and the total
