"""Peel off encoding and compression layers until readable text is left.

Many CTF puzzles hide a message under several layers: a hexdump, then gzip,
then bzip2, then a tar archive, and so on. Doing that by hand is slow and easy
to get wrong. This module tries each known layer, keeps only the ones whose
output looks real, and records every step so you can see what was done.

Only the standard library is used. ROT13 is not guessed automatically because
it can turn readable text into other readable text; pass ``rot13=True`` to
apply it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bz2
import codecs
import gzip
import io
import lzma
import re
import sys
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

DEFAULT_MAX_OUTPUT = 10 * 1024 * 1024  # refuse to expand anything past 10 MiB
TEXT_THRESHOLD = 0.95

_XXD_LINE = re.compile(r"^[0-9a-fA-F]{4,}:\s+((?:[0-9a-fA-F]{2,4} )*[0-9a-fA-F]{2,4})(?:\s{2,}|\s*$)")
_PLAIN_HEX = re.compile(r"^[0-9a-fA-F\s]+$")
_BASE64 = re.compile(r"^[A-Za-z0-9+/\s]+={0,2}\s*$")


@dataclass
class Step:
    """One successful decoding step."""

    name: str
    input_size: int
    output_size: int
    preview: str


@dataclass
class PeelResult:
    """The final bytes plus the list of steps that produced them."""

    data: bytes
    steps: list[Step] = field(default_factory=list)


def is_mostly_text(data: bytes, threshold: float = TEXT_THRESHOLD) -> bool:
    """Return True when most bytes are printable ASCII or common whitespace."""
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data) >= threshold


def _limit(size: int, max_output: int) -> None:
    if size > max_output:
        raise ValueError(f"output would be {size} bytes, above the {max_output} byte limit")


def _gunzip(data: bytes, max_output: int) -> bytes:
    decomp = zlib.decompressobj(wbits=31)
    out = decomp.decompress(data, max_output + 1)
    _limit(len(out), max_output)
    if not decomp.eof:
        raise ValueError("gzip stream is truncated")
    return out


def _bunzip2(data: bytes, max_output: int) -> bytes:
    decomp = bz2.BZ2Decompressor()
    out = decomp.decompress(data, max_output + 1)
    _limit(len(out), max_output)
    if not decomp.eof:
        raise ValueError("bzip2 stream is truncated")
    return out


def _unxz(data: bytes, max_output: int) -> bytes:
    decomp = lzma.LZMADecompressor()
    out = decomp.decompress(data, max_output + 1)
    _limit(len(out), max_output)
    if not decomp.eof:
        raise ValueError("xz stream is truncated")
    return out


def _untar(data: bytes, max_output: int) -> bytes:
    """Return the contents of a tar archive that holds exactly one regular file."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        files = [m for m in archive.getmembers() if m.isfile()]
        if len(files) != 1:
            raise ValueError(f"tar has {len(files)} regular files; expected exactly one")
        _limit(files[0].size, max_output)
        handle = archive.extractfile(files[0])
        if handle is None:
            raise ValueError("tar member could not be read")
        return handle.read()


def _unzip(data: bytes, max_output: int) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) != 1:
            raise ValueError(f"zip has {len(infos)} entries; expected exactly one")
        _limit(infos[0].file_size, max_output)
        return archive.read(infos[0])


def _hexdump(text: str) -> bytes:
    """Rebuild bytes from `xxd` style lines: `OFFSET: HEX HEX ...  ASCII`."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty hexdump")
    chunks = []
    for line in lines:
        match = _XXD_LINE.match(line)
        if not match:
            raise ValueError("line is not in xxd format")
        chunks.append(bytes.fromhex(match.group(1).replace(" ", "")))
    return b"".join(chunks)


def _plain_hex(text: str) -> bytes:
    compact = re.sub(r"\s+", "", text)
    if len(compact) % 2:
        raise ValueError("hex string has an odd number of digits")
    return bytes.fromhex(compact)


def _base64(text: str) -> bytes:
    compact = re.sub(r"\s+", "", text)
    return base64.b64decode(compact, validate=True)


def _url(text: str) -> bytes:
    if "%" not in text:
        raise ValueError("no percent escapes")
    return unquote(text).encode("utf-8", errors="surrogateescape")


def _rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")


# Binary container formats: detected by magic bytes.
_MAGIC_LAYERS: list[tuple[str, Callable[[bytes, int], bytes], Callable[[bytes], bool]]] = [
    ("gzip", _gunzip, lambda d: d.startswith(b"\x1f\x8b")),
    ("bzip2", _bunzip2, lambda d: d.startswith(b"BZh")),
    ("xz", _unxz, lambda d: d.startswith(b"\xfd7zXZ\x00")),
    ("zip", _unzip, lambda d: d.startswith(b"PK\x03\x04")),
    ("tar", _untar, lambda d: len(d) > 262 and d[257:262] == b"ustar"),
]


def _text_layers(data: bytes, max_output: int) -> list[tuple[str, bytes]]:
    """Encodings that only apply to text. Each result must look like text."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return []
    candidates: list[tuple[str, Callable[[], bytes]]] = [
        ("xxd hexdump", lambda: _hexdump(text)),
        ("plain hex", lambda: _plain_hex(text)),
        ("base64", lambda: _base64(text)),
        ("URL percent-encoding", lambda: _url(text)),
    ]
    results = []
    for name, convert in candidates:
        try:
            out = convert()
        except (ValueError, binascii.Error):
            continue
        if out and out != data and (_is_known_magic(out) or is_mostly_text(out)):
            results.append((name, out))
    return results


def _is_known_magic(data: bytes) -> bool:
    return any(check(data) for _, _, check in _MAGIC_LAYERS)


def _preview(data: bytes, width: int = 60) -> str:
    if is_mostly_text(data):
        shown = data.decode("utf-8", errors="replace").replace("\n", "\\n")
    else:
        shown = data[:width].hex()
    return shown if len(shown) <= width else shown[: width - 3] + "..."


def peel(
    data: bytes,
    *,
    max_steps: int = 25,
    max_output: int = DEFAULT_MAX_OUTPUT,
    rot13: bool = False,
) -> PeelResult:
    """Repeatedly undo the first layer that fits until none does.

    Each step is recorded. The loop stops after ``max_steps`` so a file that
    keeps decoding into new data cannot run forever.
    """
    result = PeelResult(data=data)
    for _ in range(max_steps):
        step = _one_step(result.data, max_output=max_output)
        if step is None and rot13:
            step = _rot13_step(result.data)
        if step is None:
            break
        name, new_data = step
        result.steps.append(Step(name, len(result.data), len(new_data), _preview(new_data)))
        result.data = new_data
    return result


_COMMON_WORDS = {"the", "a", "an", "is", "of", "and", "to", "in", "it", "password", "flag", "key", "for"}


def _english_score(data: bytes) -> int:
    words = re.findall(rb"[a-z]+", data.lower())
    return sum(1 for word in words if word.decode() in _COMMON_WORDS)


def _rot13_step(data: bytes) -> tuple[str, bytes] | None:
    """Apply ROT13 only when it makes the text more English-like.

    ROT13 maps readable text to other readable text, so it is never applied
    automatically. It is used only with ``--rot13`` and only when it produces
    more common English words than the input.
    """
    rotated = _rot13(data)
    if rotated != data and _english_score(rotated) > _english_score(data):
        return "rot13", rotated
    return None


def _one_step(data: bytes, *, max_output: int) -> tuple[str, bytes] | None:
    """Return the first layer that decodes ``data``, or None."""
    for name, decode, detect in _MAGIC_LAYERS:
        if detect(data):
            try:
                return name, decode(data, max_output)
            except (ValueError, OSError, EOFError, zlib.error, lzma.LZMAError, tarfile.TarError, zipfile.BadZipFile):
                continue
    layers = _text_layers(data, max_output)
    if layers:
        return layers[0]
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Undo hexdump, base64, compression and archive layers.")
    parser.add_argument("input", help="file to decode, or - for standard input")
    parser.add_argument("--rot13", action="store_true", help="also try ROT13 when nothing else fits")
    parser.add_argument("--max-steps", type=int, default=25, help="stop after this many layers (default 25)")
    parser.add_argument("--max-output-mb", type=float, default=10.0, help="refuse to expand past this size")
    parser.add_argument("--output", type=Path, help="write the final bytes to this file")
    args = parser.parse_args(argv)

    raw = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
    result = peel(
        raw,
        max_steps=args.max_steps,
        max_output=int(args.max_output_mb * 1024 * 1024),
        rot13=args.rot13,
    )
    for number, step in enumerate(result.steps, start=1):
        print(f"step {number}: {step.name} ({step.input_size} -> {step.output_size} bytes)", file=sys.stderr)
    if args.output:
        args.output.write_bytes(result.data)
        print(f"wrote {len(result.data)} bytes to {args.output}", file=sys.stderr)
    elif is_mostly_text(result.data):
        sys.stdout.write(result.data.decode("utf-8", errors="replace"))
        if not result.data.endswith(b"\n"):
            sys.stdout.write("\n")
    else:
        print(f"final data is binary ({len(result.data)} bytes); use --output to save it", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
