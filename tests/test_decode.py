import bz2
import gzip
import io
import lzma
import tarfile
import zipfile

import pytest

from ctf_tools.decode import main, peel


def xxd_dump(data: bytes) -> str:
    """Format bytes the way `xxd` prints them: offset, 2-byte groups, ASCII column."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        groups = " ".join(chunk[i : i + 2].hex() for i in range(0, len(chunk), 2))
        ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}: {groups:<39}  {ascii_col}")
    return "\n".join(lines) + "\n"


SECRET = b"The password is practice-value-42\n"


def test_plain_text_is_left_alone():
    result = peel(SECRET)
    assert result.data == SECRET
    assert result.steps == []


def test_hexdump_gzip_bzip2_chain_is_fully_undone():
    layered = bz2.compress(gzip.compress(SECRET))
    result = peel(xxd_dump(layered).encode())
    assert result.data == SECRET
    assert [s.name for s in result.steps] == ["xxd hexdump", "bzip2", "gzip"]


def test_plain_hex_and_base64_and_url_are_decoded():
    assert peel(SECRET.hex().encode()).data == SECRET
    assert peel(b"VGhlIHBhc3N3b3JkIGlzIHByYWN0aWNlLXZhbHVlLTQyCg==").data == SECRET
    url = "".join(f"%{b:02X}" for b in b"The password is practice").encode()
    assert peel(url).data == b"The password is practice"


def test_tar_with_one_file_is_unpacked():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("data.txt")
        info.size = len(SECRET)
        archive.addfile(info, io.BytesIO(SECRET))
    result = peel(buffer.getvalue())
    assert result.data == SECRET
    assert [s.name for s in result.steps] == ["tar"]


def test_tar_with_several_files_is_not_guessed():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in ("a.txt", "b.txt"):
            info = tarfile.TarInfo(name)
            info.size = len(SECRET)
            archive.addfile(info, io.BytesIO(SECRET))
    result = peel(buffer.getvalue())
    assert result.steps == []


def test_zip_with_one_entry_is_read():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("inner.txt", SECRET)
    assert peel(buffer.getvalue()).data == SECRET


def test_xz_layer_is_undone():
    assert peel(lzma.compress(SECRET)).data == SECRET


def test_rot13_is_only_used_when_requested():
    rotated = b"Gur cnffjbeq vf cenpgvpr\n"
    assert peel(rotated).data == rotated
    assert peel(rotated, rot13=True).data == b"The password is practice\n"


def test_decompression_limit_stops_large_expansion():
    bomb = gzip.compress(b"\x00" * (1024 * 1024))
    result = peel(bomb, max_output=1000)
    assert result.data == bomb
    assert result.steps == []


def test_truncated_gzip_is_not_accepted():
    truncated = gzip.compress(SECRET)[:-6]
    assert peel(truncated).steps == []


def test_max_steps_limits_the_loop():
    layered = bz2.compress(gzip.compress(SECRET))
    result = peel(layered, max_steps=1)
    assert len(result.steps) == 1
    assert result.data == gzip.compress(SECRET)


def test_cli_writes_output_file(tmp_path, capsys):
    source = tmp_path / "layers.txt"
    source.write_text(xxd_dump(gzip.compress(SECRET)))
    target = tmp_path / "final.txt"
    assert main([str(source), "--output", str(target)]) == 0
    assert target.read_bytes() == SECRET
    err = capsys.readouterr().err
    assert "step 1: xxd hexdump" in err
    assert "step 2: gzip" in err


def test_cli_prints_text_to_stdout(tmp_path, capsys):
    source = tmp_path / "text.txt"
    source.write_bytes(gzip.compress(SECRET))
    assert main([str(source)]) == 0
    out = capsys.readouterr()
    assert "practice-value-42" in out.out
    assert "step 1: gzip" in out.err


def test_cli_refuses_to_print_binary(tmp_path, capsys):
    source = tmp_path / "binary.bin"
    source.write_bytes(bytes(range(128, 255)) * 4)
    assert main([str(source)]) == 1
    assert "binary" in capsys.readouterr().err


@pytest.mark.parametrize("payload", [b"", b"hello"])
def test_short_or_empty_input_is_unchanged(payload):
    assert peel(payload).data == payload
