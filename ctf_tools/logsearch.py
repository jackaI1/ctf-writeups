"""Search web and login logs for suspicious lines and summarise who sent them.

Practice challenges often hand you a web server log or an SSH log and ask
which address tried an attack, or how many logins failed. Reading thousands of
lines by hand is slow, so this tool filters them with a regular expression (or
a named preset), then counts the source addresses, paths and status codes.

It reads plain text and ``.gz`` files and understands two common formats:
Apache/Nginx "combined" access logs and OpenSSH "Failed password" messages.
Lines that do not match a known format are still searched for the pattern.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TextIO

# Patterns for common attacks, written to match the raw request line or message.
PRESETS: dict[str, str] = {
    "traversal": r"(\.\./|\.\.\\|%2e%2e|%252e%252e)",
    "sqli": r"(union(\s|\+|%20)+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\))",
    "xss": r"(<script|%3cscript|onerror\s*=|javascript:)",
    "ssh-failed": r"Failed password for",
    "scanner": r"(/\.env|/wp-login\.php|/phpmyadmin|/\.git/)",
}

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)
_SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port")


@dataclass
class Match:
    """One matching line, with the fields that could be read from it."""

    line_number: int
    text: str
    ip: str | None = None
    status: int | None = None
    path: str | None = None


@dataclass
class Summary:
    """Counts over all matching lines. Only the first ``keep`` matches are stored."""

    lines_read: int = 0
    match_count: int = 0
    matches: list[Match] = field(default_factory=list)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    status_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "lines_read": self.lines_read,
            "match_count": self.match_count,
            "top_ips": [list(pair) for pair in self.top_ips],
            "top_paths": [list(pair) for pair in self.top_paths],
            "status_counts": self.status_counts,
            "matches": [asdict(m) for m in self.matches],
        }


def open_log(path: Path) -> TextIO:
    """Open a log as text, decompressing it when the name ends in .gz."""
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse_fields(line: str) -> dict:
    """Pull the source address, status and path out of a known log format."""
    fields: dict = {}
    combined = _COMBINED.match(line)
    if combined:
        fields["ip"] = combined["ip"]
        fields["status"] = int(combined["status"])
        request_parts = combined["request"].split()
        if len(request_parts) >= 2:
            fields["path"] = request_parts[1]
        return fields
    ssh = _SSH_FAILED.search(line)
    if ssh:
        fields["ip"] = ssh["ip"]
    return fields


def search(
    lines: Iterable[str],
    *,
    pattern: str,
    status: int | None = None,
    ip: str | None = None,
    top: int = 10,
    keep: int = 20,
) -> Summary:
    """Filter lines by regex, status and address, then count the results."""
    regex = re.compile(pattern)
    summary = Summary()
    ip_counts: Counter[str] = Counter()
    path_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()

    for number, raw in enumerate(lines, start=1):
        summary.lines_read += 1
        line = raw.rstrip("\n")
        fields = parse_fields(line)
        if status is not None and fields.get("status") != status:
            continue
        if ip is not None and fields.get("ip") != ip:
            continue
        if not regex.search(line):
            continue
        summary.match_count += 1
        if len(summary.matches) < keep:
            summary.matches.append(Match(line_number=number, text=line, **fields))
        if fields.get("ip"):
            ip_counts[fields["ip"]] += 1
        if fields.get("path"):
            path_counts[fields["path"]] += 1
        if fields.get("status") is not None:
            status_counts[str(fields["status"])] += 1

    summary.top_ips = ip_counts.most_common(top)
    summary.top_paths = path_counts.most_common(top)
    summary.status_counts = dict(status_counts.most_common())
    return summary


def iter_files(paths: list[Path]) -> Iterator[str]:
    """Yield lines from every file in order, so large logs are never fully loaded."""
    for path in paths:
        with open_log(path) as handle:
            yield from handle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Search logs and summarise the matching sources.")
    parser.add_argument("logs", nargs="+", type=Path, help="log files (plain or .gz)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--match", help="regular expression to search for")
    group.add_argument("--preset", choices=sorted(PRESETS), help="use a built-in attack pattern")
    parser.add_argument("--status", type=int, help="only lines with this HTTP status")
    parser.add_argument("--ip", help="only lines from this source address")
    parser.add_argument("--top", type=int, default=10, help="how many top sources and paths to list")
    parser.add_argument("--show", type=int, default=20, help="how many matching lines to print (default 20)")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = parser.parse_args(argv)

    pattern = args.match if args.match else PRESETS[args.preset]
    summary = search(
        iter_files(args.logs),
        pattern=pattern,
        status=args.status,
        ip=args.ip,
        top=args.top,
        keep=args.show,
    )

    if args.json:
        json.dump(summary.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print(f"read {summary.lines_read} lines, {summary.match_count} matched")
    if summary.top_ips:
        print("top sources:")
        for address, count in summary.top_ips:
            print(f"  {count:6d}  {address}")
    if summary.top_paths:
        print("top paths:")
        for path, count in summary.top_paths:
            print(f"  {count:6d}  {path}")
    if summary.status_counts:
        print("status codes:", ", ".join(f"{code}={count}" for code, count in summary.status_counts.items()))
    for match in summary.matches:
        print(f"{match.line_number}: {match.text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
