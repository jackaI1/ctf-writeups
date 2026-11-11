import gzip
import json

from ctf_tools.logsearch import PRESETS, main, search

ACCESS_LOG = [
    '203.0.113.5 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326\n',
    '198.51.100.7 - - [10/Oct/2026:13:55:37 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 404 153\n',
    '198.51.100.7 - - [10/Oct/2026:13:55:38 +0000] "GET /download?file=%2e%2e/%2e%2e/etc/shadow HTTP/1.1" 403 153\n',
    '192.0.2.44 - - [10/Oct/2026:13:55:40 +0000] "GET /search?q=1+union+select+password HTTP/1.1" 500 80\n',
    '198.51.100.7 - - [10/Oct/2026:13:55:41 +0000] "GET /.env HTTP/1.1" 404 20\n',
]

AUTH_LOG = [
    "Oct 10 13:56:01 host sshd[811]: Failed password for root from 203.0.113.9 port 4022 ssh2\n",
    "Oct 10 13:56:02 host sshd[812]: Failed password for invalid user admin from 203.0.113.9 port 4023 ssh2\n",
    "Oct 10 13:56:03 host sshd[813]: Accepted password for alice from 192.0.2.10 port 5000 ssh2\n",
]


def test_traversal_preset_finds_encoded_and_plain_attempts():
    summary = search(ACCESS_LOG, pattern=PRESETS["traversal"])
    assert summary.match_count == 2
    assert summary.top_ips == [("198.51.100.7", 2)]
    assert summary.status_counts == {"404": 1, "403": 1}


def test_status_filter_limits_matches():
    summary = search(ACCESS_LOG, pattern=PRESETS["scanner"], status=404)
    assert summary.match_count == 1
    assert summary.matches[0].path == "/.env"


def test_ip_filter_and_line_numbers():
    summary = search(ACCESS_LOG, pattern=".", ip="192.0.2.44")
    assert summary.lines_read == len(ACCESS_LOG)
    assert [m.line_number for m in summary.matches] == [4]


def test_sqli_preset_matches_union_select():
    summary = search(ACCESS_LOG, pattern=PRESETS["sqli"])
    assert summary.match_count == 1
    assert summary.matches[0].ip == "192.0.2.44"


def test_ssh_failures_are_counted_by_source():
    summary = search(AUTH_LOG, pattern=PRESETS["ssh-failed"])
    assert summary.match_count == 2
    assert summary.top_ips == [("203.0.113.9", 2)]


def test_only_first_matches_are_kept_but_all_are_counted():
    summary = search(AUTH_LOG, pattern="Failed", keep=1)
    assert summary.match_count == 2
    assert len(summary.matches) == 1


def test_cli_reads_gzip_and_json_output(tmp_path, capsys):
    plain = tmp_path / "access.log"
    plain.write_text("".join(ACCESS_LOG))
    compressed = tmp_path / "access.log.gz"
    compressed.write_bytes(gzip.compress("".join(AUTH_LOG).encode()))

    assert main([str(plain), str(compressed), "--preset", "ssh-failed", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["match_count"] == 2
    assert data["top_ips"] == [["203.0.113.9", 2]]


def test_cli_text_output_lists_sources(tmp_path, capsys):
    log = tmp_path / "access.log"
    log.write_text("".join(ACCESS_LOG))
    assert main([str(log), "--match", r"\.\./", "--top", "3"]) == 0
    out = capsys.readouterr().out
    assert "read 5 lines, 1 matched" in out
    assert "198.51.100.7" in out
