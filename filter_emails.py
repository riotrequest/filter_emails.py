#!/usr/bin/env python3
"""Collect review candidates from GreenArrow's possible-spamtrap report."""

from __future__ import annotations

import argparse
import contextlib
import csv
import ipaddress
import json
import logging
import math
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TextIO

DEFAULT_COMMAND = "/var/hvmail/bin/hvmail_get_possible_spamtrap_hits"
QUERY_STEP = 179  # One-second overlap avoids depending on endpoint inclusivity.
LOG = logging.getLogger("filter_emails")

# Use GreenArrow's installed database/time/path helpers, without exposing credentials.
# This inventory query reads metadata only; recipient data stays in read-only SQLite.
SUMMARY_INVENTORY = r"""
use HVMail::Database;
use HVMail::Time;
use HVMail::Util;
use JSON::PP;
my ($start, $end) = @ARGV;
my $dbh = HVMail::Database::connect();
$dbh->rollback();
$dbh->do('SET TRANSACTION READ ONLY');
my $ips = $dbh->selectall_arrayref('SELECT id, ipaddr FROM mr_ipaddr ORDER BY id');
my $relays = $dbh->selectall_arrayref('SELECT id, server, out_ipaddr FROM mr_relay ORDER BY id');
my $first = $dbh->quote(HVMail::Time::unix_to_tai($start));
my $last = $dbh->quote(HVMail::Time::unix_to_tai($end));
my $sends = $dbh->selectall_arrayref(qq[
    SELECT id, sendid FROM sends WHERE
    ($first <= ram_last AND $last >= ram_first) OR
    ($first <= disk_last AND $last >= disk_first) OR
    ($first <= bounce_last AND $last >= bounce_first)
    ORDER BY id
]);
my @summaries = map {
    {sendid => $_->[1], path => HVMail::Util::get_send_summary_filename($_->[0], 0)}
} @$sends;
$dbh->rollback();
$dbh->disconnect();
print encode_json({ips => $ips, relays => $relays, summaries => \@summaries});
"""

SUMMARY_SQL = """
SELECT localpart, domainid.domain, smtp_result_code,
       CAST(smtp_result_time AS TEXT), status_messages.message, smtp_result_outmtaid
FROM messages
LEFT JOIN status_messages ON status_messages.id = messages.smtp_result_smsgid
LEFT JOIN domainid ON domainid.id = messages.domain
WHERE ? <= smtp_result_time AND smtp_result_time < ?
ORDER BY injtime, msguid
"""


class ScanError(Exception):
    """A scan cannot produce a complete, trustworthy result."""


def local_timestamp(value: datetime) -> int:
    """Reject local wall times the command cannot express unambiguously."""
    timestamp = int(value.timestamp())
    if (
        datetime.fromtimestamp(timestamp) != value
        or value.replace(fold=0).timestamp() != value.replace(fold=1).timestamp()
    ):
        raise ValueError(f"ambiguous or nonexistent server-local time: {value}")
    return timestamp


def parse_time(value: str) -> int:
    for pattern in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
    ):
        try:
            parsed = datetime.strptime(value.replace("T", " "), pattern)
        except ValueError:
            continue
        return local_timestamp(parsed)
    raise ValueError(f"invalid timestamp {value!r}; use YYYY-MM-DD HH:MM[:SS]")


def merge_windows(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if end <= start:
            raise ValueError("each window's end must be later than its start")
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def commands(binary: str, ips: list[str], windows: list[tuple[int, int]]):
    """Tile [start, end) using the documented [-60s, +120s] query window."""
    for ip in ips:
        for start, end in windows:
            for cursor in range(start, end, QUERY_STEP):
                anchor = datetime.fromtimestamp(cursor + 59)
                local_timestamp(anchor)
                yield [
                    binary,
                    "--dd-mm-yyyy-timestamp",
                    anchor.strftime("%d/%m/%Y %H:%M:%S"),
                    ip,
                ]


def parse_report(report: str) -> set[tuple[str, Decimal, str]]:
    """Accept the command's legacy report and current processed log formats."""
    records: set[tuple[str, Decimal, str]] = set()
    for number, line in enumerate(report.splitlines(), 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        # GreenArrow can report unavailable logs even with a zero exit status.
        if re.match(
            r"\s*(?:ACTUAL\s*==>|missing\s+\d+\s+seconds\b)", line, re.IGNORECASE
        ):
            raise ScanError(
                "GreenArrow reports unavailable logs; requested coverage is incomplete"
            )
        if line.startswith("email=<"):
            match = re.match(
                r"email=<([^>]*)>\s+smtp_result_time=<([^>]*)>(?:\s|$)", line
            )
            if not match:
                raise ScanError(f"malformed legacy report record on line {number}")
            email, timestamp = match.groups()
        elif line.startswith("timestamp=<"):
            match = re.match(
                r"timestamp=<([^>]*)>\s+channel=<[^>]*>\s+status=<[^>]*>\s+"
                r"is_retry=<[^>]*>\s+msguid=<[^>]*>\s+recipient=<([^>]*)>(?:\s|$)",
                line,
            )
            if not match:
                raise ScanError(f"malformed human-readable record on line {number}")
            timestamp, email = match.groups()
        elif "\t" in line:
            columns = line.split("\t")
            if len(columns) < 12 or columns[1] not in {"local", "remote"}:
                raise ScanError(f"malformed processed logfile record on line {number}")
            timestamp, email = columns[0], columns[5]
        elif re.match(r"(?:Starting|Ending)\s*=", line):
            continue
        else:
            raise ScanError(
                f"unrecognized GreenArrow output on line {number}; refusing incomplete results"
            )
        email = email.strip()
        if not email or "@" not in email or any(c in email for c in "\r\n\t\x00"):
            raise ScanError(f"invalid recipient on line {number}")
        try:
            epoch = Decimal(timestamp)
        except InvalidOperation as exc:
            raise ScanError(f"invalid delivery timestamp on line {number}") from exc
        if not epoch.is_finite():
            raise ScanError(f"invalid delivery timestamp on line {number}")
        records.add((email, epoch, line))
    return records


def run_query(command: list[str], timeout: float) -> set[tuple[str, Decimal, str]]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"GreenArrow timed out after {timeout:g}s") from exc
    if result.returncode:
        raise ScanError(
            f"GreenArrow exited with status {result.returncode}: {result.stderr.strip()}"
        )
    # The native command logs these progress lines even on successful queries.
    # Unknown diagnostics (including missing summary files) still fail closed.
    progress = (
        rf"={{4,}} {re.escape(command[-2])} {re.escape(command[-1])}",
        r"checking sendid \([^\r\n]*\) \d+/\d+",
        r"send_summary_filename = /[^\r\n]+",
    )
    diagnostics = [
        line
        for line in result.stderr.splitlines()
        if line.strip() and not any(re.fullmatch(pattern, line) for pattern in progress)
    ]
    if diagnostics:
        raise ScanError(
            f"GreenArrow wrote diagnostics to stderr: {'; '.join(diagnostics)}"
        )
    return parse_report(result.stdout)


def summary_inventory(windows: list[tuple[int, int]], timeout: float) -> dict:
    try:
        result = subprocess.run(
            [
                "/var/hvmail/libexec/perl",
                "-I/var/hvmail/perllib",
                "-e",
                SUMMARY_INVENTORY,
                str(windows[0][0]),
                str(windows[-1][1]),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError("GreenArrow summary inventory timed out") from exc
    if result.returncode or result.stderr.strip():
        raise ScanError(f"GreenArrow summary inventory failed: {result.stderr.strip()}")
    inventory = json.loads(result.stdout)
    if (
        not isinstance(inventory, dict)
        or not isinstance(inventory.get("ips"), list)
        or not isinstance(inventory.get("summaries"), list)
    ):
        raise ScanError("invalid GreenArrow summary inventory")
    if not inventory["ips"]:
        raise ScanError("no sending IPs are configured in GreenArrow")
    return inventory


def scan_summaries(
    inventory: dict,
    windows: list[tuple[int, int]],
    failures: list[dict[str, str]] | None = None,
    include_relays: bool = False,
) -> list[dict[str, str]]:
    """Collect the native command's last-result evidence in one pass for all IPs."""
    ips = {str(key): str(ipaddress.ip_address(ip)) for key, ip in inventory["ips"]}
    relays = {}
    if include_relays:
        for key, server, bound_ip in inventory.get("relays", []):
            route_id = str(key)
            ips[route_id] = str(ipaddress.ip_address(bound_ip)) if bound_ip else None
            relays[route_id] = str(server)
    results: dict[tuple[str, str], dict[str, str]] = {}
    status_names = {
        1: "accepted",
        2: "failed",
        3: "expired",
        4: "deferred",
        5: "deferred_throttle",
    }
    for index, summary in enumerate(inventory["summaries"], 1):
        path = Path(summary["path"])
        LOG.info("Summary %d/%d: %s", index, len(inventory["summaries"]), path)
        try:
            # URI mode=ro refuses missing files and prevents creating/modifying databases.
            with contextlib.closing(
                sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
            ) as database:
                for (
                    localpart,
                    domain,
                    status,
                    timestamp,
                    message,
                    outmtaid,
                ) in database.execute(SUMMARY_SQL, (windows[0][0], windows[-1][1])):
                    outmtaid = str(outmtaid)
                    if outmtaid not in ips or not any(
                        start <= Decimal(timestamp) < end for start, end in windows
                    ):
                        continue
                    raw = (
                        f"email=<{localpart}@{domain}> smtp_result_time=<{timestamp}> "
                        f"smtp_result=<{status_names.get(status, status)}> "
                        f"smtp_result_message=<{message or ''}> sendid=<{summary['sendid']}>"
                    )
                    # Share the same validation and record representation as native lookups.
                    records = parse_report(raw)
                    for email, epoch, line in records:
                        ip = ips[outmtaid]
                        results[(outmtaid, line)] = {
                            "ip": ip,
                            "email": email,
                            "timestamp": str(epoch),
                            "raw": line,
                            "outmtaid": outmtaid,
                            "route_type": "relay" if outmtaid in relays else "direct",
                            "relay_server": relays.get(outmtaid),
                        }
        except (OSError, sqlite3.Error, ScanError, ValueError) as exc:
            if failures is None:
                raise ScanError(f"summary {path}: {exc}") from exc
            failures.append(
                {
                    "summary_file": str(path),
                    "sendid": str(summary["sendid"]),
                    "error": str(exc),
                }
            )
            LOG.warning("Summary unavailable or incomplete: %s: %s", path, exc)
    return sorted(
        results.values(),
        key=lambda row: (
            row["ip"] or "",
            Decimal(row["timestamp"]),
            row["email"],
            row["raw"],
        ),
    )


def scan(
    binary: str,
    ips: list[str],
    windows: list[tuple[int, int]],
    timeout: float,
    failures: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    deliveries: dict[tuple[str, str], dict[str, str]] = {}
    total = len(ips) * sum(
        (end - start + QUERY_STEP - 1) // QUERY_STEP for start, end in windows
    )
    for index, command in enumerate(commands(binary, ips, windows), 1):
        LOG.info("Query %d/%d: %s at %s", index, total, command[-1], command[-2])
        try:
            records = run_query(command, timeout)
        except (ScanError, OSError, ValueError) as exc:
            if failures is None:
                raise ScanError(f"{command[-1]} at {command[-2]}: {exc}") from exc
            failures.append(
                {"ip": command[-1], "query_timestamp": command[-2], "error": str(exc)}
            )
            LOG.warning("Query failed for %s at %s: %s", command[-1], command[-2], exc)
            continue
        for email, timestamp, raw in records:
            if any(start <= timestamp < end for start, end in windows):
                deliveries[(command[-1], raw)] = {
                    "ip": command[-1],
                    "email": email,
                    "timestamp": str(timestamp),
                    "raw": raw,
                }
    return sorted(
        deliveries.values(),
        key=lambda row: (
            row["ip"],
            Decimal(row["timestamp"]),
            row["email"],
            row["raw"],
        ),
    )


def write_report(
    stream: TextIO,
    deliveries: list[dict[str, str]],
    args: argparse.Namespace,
    windows: list[tuple[int, int]],
) -> None:
    emails = sorted({row["email"] for row in deliveries})
    if args.format == "csv":
        csv.writer(stream).writerows((email,) for email in emails)
    else:
        json.dump(
            {
                "candidate_count": len(emails),
                "emails": emails,
                "ips": args.ip,
                "delivery_count": len(deliveries),
                "deliveries": deliveries,
                "complete": not args.failures,
                "failed_queries": args.failures,
                "collection_method": "send_summaries"
                if args.all_ips
                else "native_window_queries",
                "includes_relays": args.include_relays,
                "windows": [
                    {"start_epoch": start, "end_epoch_exclusive": end}
                    for start, end in windows
                ],
                "classification": "review_candidates_not_confirmed_spamtraps",
            },
            stream,
            indent=2,
            ensure_ascii=False,
        )
        stream.write("\n")


def save_report(
    deliveries: list[dict[str, str]],
    args: argparse.Namespace,
    windows: list[tuple[int, int]],
) -> None:
    if args.output == "-":
        write_report(sys.stdout, deliveries, args, windows)
        return
    output = Path(args.output)
    temporary = None
    try:
        # Same directory keeps os.replace atomic; mkstemp restricts permissions on POSIX.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            write_report(stream, deliveries, args, windows)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def interactive_args() -> list[str]:
    date = datetime.strptime(input("Enter the date (dd/mm/yyyy): "), "%d/%m/%Y")
    ip = input("Enter the IP address: ").strip()
    start = int(input("Enter the start hour (0-23): "))
    end = int(input("Enter the end hour (0-23, inclusive): "))
    if not 0 <= start <= end <= 23:
        raise ValueError("hours must satisfy 0 <= start <= end <= 23")
    return [
        "--ip",
        ip,
        "--window",
        (date + timedelta(hours=start)).isoformat(" "),
        (date + timedelta(hours=end + 1)).isoformat(" "),
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Times use the GreenArrow server's local timezone; window ends are exclusive.",
    )
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument(
        "--ip",
        action="append",
        help="sending IP; repeat for multiple IPs",
    )
    targets.add_argument(
        "--all-ips",
        action="store_true",
        help="collect all configured IPs in one read-only pass through GreenArrow send summaries",
    )
    parser.add_argument(
        "--include-relays",
        action="store_true",
        help="with --all-ips, also collect configured SMTP relay routes; ip is their local connection source, not the provider's delivery IP",
    )
    parser.add_argument(
        "--window",
        nargs=2,
        action="append",
        required=True,
        metavar=("START", "END"),
        help="YYYY-MM-DD HH:MM[:SS]; repeat for multiple ranges",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="email_addresses.csv",
        help="output path, or - for stdout",
    )
    parser.add_argument(
        "--format",
        choices=("csv", "json"),
        default="csv",
        help="headerless CSV (default) or JSON",
    )
    parser.add_argument(
        "--command", default=DEFAULT_COMMAND, help="path to the GreenArrow executable"
    )
    parser.add_argument(
        "--timeout", type=float, default=120, help="seconds per query (default: 120)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print commands without running them or writing a report",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="keep successful queries if others fail; requires --format json; exits 3 if incomplete",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show progress on stderr"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        if not sys.stdin.isatty():
            parser.print_help(sys.stderr)
            return 2
        try:
            arguments = interactive_args()
        except (ValueError, EOFError) as exc:
            parser.error(str(exc))
        except KeyboardInterrupt:
            print("Cancelled.", file=sys.stderr)
            return 130
    args = parser.parse_args(arguments)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    try:
        args.ip = list(
            dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in args.ip or [])
        )
        windows = merge_windows(
            [(parse_time(start), parse_time(end)) for start, end in args.window]
        )
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("--timeout must be a finite positive number")
        if not args.command or args.command.startswith("-"):
            raise ValueError("--command must name an executable")
        if args.allow_partial and args.format != "json":
            raise ValueError(
                "--allow-partial requires --format json so coverage failures remain visible"
            )
        if args.include_relays and not args.all_ips:
            raise ValueError("--include-relays requires --all-ips")
    except (ValueError, OverflowError, OSError) as exc:
        parser.error(str(exc))
    try:
        inventory = summary_inventory(windows, args.timeout) if args.all_ips else None
        if inventory is not None:
            args.ip = list(
                dict.fromkeys(
                    str(ipaddress.ip_address(ip)) for _, ip in inventory["ips"]
                )
            )
        if args.dry_run:
            if inventory is not None:
                print(
                    json.dumps(
                        {
                            "ips": args.ip,
                            "relays": inventory.get("relays", [])
                            if args.include_relays
                            else [],
                            "summaries": inventory["summaries"],
                        },
                        indent=2,
                    )
                )
                return 0
            for command in commands(args.command, args.ip, windows):
                print(shlex.join(command))
            return 0
        args.failures = []
        deliveries = (
            scan_summaries(
                inventory,
                windows,
                args.failures if args.allow_partial else None,
                args.include_relays,
            )
            if inventory is not None
            else scan(
                args.command,
                args.ip,
                windows,
                args.timeout,
                args.failures if args.allow_partial else None,
            )
        )
        save_report(deliveries, args, windows)
        count = len({row["email"] for row in deliveries})
        if args.failures:
            print(
                f"Saved INCOMPLETE report to {args.output}: {count} candidates; {len(args.failures)} queries failed.",
                file=sys.stderr,
            )
            return 3
        print(
            f"Saved {count} unique review candidates ({len(deliveries)} delivery records) to {args.output}.",
            file=sys.stderr,
        )
        return 0
    except KeyboardInterrupt:
        print("Cancelled; no report was saved.", file=sys.stderr)
        return 130
    except (ScanError, OSError, ValueError, OverflowError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
