import contextlib
import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from decimal import Decimal
from itertools import pairwise
from pathlib import Path
from unittest.mock import patch

import filter_emails as app


def legacy(email="person@example.com", timestamp="100", sendid="send1"):
    return f"email=<{email}> smtp_result_time=<{timestamp}> smtp_result=<accepted> smtp_result_message=<> sendid=<{sendid}>"


class ReportTests(unittest.TestCase):
    def test_legacy_preserves_precision_and_all_evidence(self):
        raw = legacy(timestamp="100.00000000001")
        self.assertEqual(
            app.parse_report(raw),
            {("person@example.com", Decimal("100.00000000001"), raw)},
        )

    def test_current_human_format(self):
        raw = "timestamp=<100.5> channel=<remote> status=<success> is_retry=<0> msguid=<99.9> recipient=<person@example.com> sender=<sender@example.com> message=<ok>"
        self.assertEqual(
            next(iter(app.parse_report(raw)))[:2],
            ("person@example.com", Decimal("100.5")),
        )

    def test_current_tab_format_with_empty_trailing_columns(self):
        raw = "100.5\tremote\tsuccess\t0\t99.9\tperson@example.com\tsender@example.com\t\tsend1\t\t99\t"
        self.assertEqual(next(iter(app.parse_report(raw)))[2], raw)

    def test_missing_logs_and_unknown_formats_fail_closed(self):
        for report in (
            " ACTUAL==> Wed Dec 31 18:00:00 1969",
            "missing 215552 seconds",
            "new unknown output",
            "email=<person@example.com>",
            legacy(timestamp="NaN"),
            legacy(timestamp="Infinity"),
            legacy(timestamp="bad"),
            legacy(email=""),
            "1\tremote\tx",
        ):
            with self.subTest(report=report), self.assertRaises(app.ScanError):
                app.parse_report(report)

    def test_preamble_and_empty_result(self):
        self.assertEqual(
            app.parse_report("Starting = requested date\nEnding = requested date\n\n"),
            set(),
        )


class PlanningTests(unittest.TestCase):
    def test_merge_overlapping_adjacent_and_duplicate_windows(self):
        self.assertEqual(
            app.merge_windows([(20, 30), (0, 10), (5, 20), (0, 10), (40, 50)]),
            [(0, 30), (40, 50)],
        )
        for window in ((10, 10), (11, 10)):
            with self.assertRaises(ValueError):
                app.merge_windows([window])

    def test_query_coverage_for_short_long_and_unaligned_windows(self):
        base = app.parse_time("2026-10-01 09:00:17")
        for duration in (1, 60, 179, 180, 181, 3600, 86400):
            with self.subTest(duration=duration):
                plan = list(
                    app.commands(
                        "binary with spaces", ["192.0.2.1"], [(base, base + duration)]
                    )
                )
                anchors = [app.parse_time(command[-2]) for command in plan]
                self.assertLess(anchors[0] - 60, base)
                self.assertGreaterEqual(anchors[-1] + 120, base + duration)
                self.assertTrue(all(b - a == 179 for a, b in pairwise(anchors)))
                self.assertEqual(plan[0][0], "binary with spaces")
        self.assertEqual(
            len(list(app.commands("binary", ["192.0.2.1"], [(base, base + 3600)]))), 21
        )

    def test_date_formats(self):
        self.assertEqual(
            app.parse_time("01/10/2026 09:00"), app.parse_time("2026-10-01T09:00:00")
        )
        for value in ("2026-02-30 09:00", "2026-10-01 24:00", "2026-10-01T09:00Z"):
            with self.assertRaises(ValueError):
                app.parse_time(value)

    @unittest.skipUnless(hasattr(time, "tzset"), "POSIX local timezone handling")
    def test_dst_times_are_rejected(self):
        previous = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/New_York"
            time.tzset()
            for value in ("2026-03-08 02:30", "2026-11-01 01:30"):
                with self.assertRaisesRegex(ValueError, "ambiguous or nonexistent"):
                    app.parse_time(value)
            # A range spanning a repeated hour must also fail, even with valid endpoints.
            windows = [
                (app.parse_time("2026-11-01 00:30"), app.parse_time("2026-11-01 03:30"))
            ]
            with self.assertRaises(ValueError):
                list(app.commands("binary", ["192.0.2.1"], windows))
        finally:
            if previous is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous
            time.tzset()


class ScanTests(unittest.TestCase):
    def test_exact_boundaries_dedup_and_distinct_deliveries(self):
        base = app.parse_time("2026-10-01 09:00")
        records = []
        for offset, sendid in (
            ("99.9", "send1"),
            ("100", "send1"),
            ("279.999999999999999999", "send1"),
            ("280", "send1"),
            ("280", "send2"),
            ("460", "send1"),
        ):
            whole, separator, fraction = offset.partition(".")
            timestamp = str(base + int(whole)) + separator + fraction
            records.append(legacy(timestamp=timestamp, sendid=sendid))
        output = "\n".join(records)
        completed = subprocess.CompletedProcess([], 0, output, "")
        with patch.object(app.subprocess, "run", return_value=completed) as run:
            rows = app.scan(
                "binary", ["192.0.2.1", "192.0.2.2"], [(base + 100, base + 460)], 7
            )
        self.assertEqual(len(rows), 8)  # Four distinct records per source IP.
        self.assertEqual({row["email"] for row in rows}, {"person@example.com"})
        self.assertEqual(run.call_args.kwargs["timeout"], 7)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_errors_do_not_become_empty_success(self):
        base = app.parse_time("2026-10-01 09:00")
        for result in (
            subprocess.CompletedProcess([], 1, "", "failed"),
            subprocess.CompletedProcess([], 0, "", "warning"),
        ):
            with (
                patch.object(app.subprocess, "run", return_value=result),
                self.assertRaises(app.ScanError),
            ):
                app.scan("binary", ["192.0.2.1"], [(base, base + 100)], 1)
        with (
            patch.object(
                app.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired("binary", 1),
            ),
            self.assertRaisesRegex(app.ScanError, "timed out"),
        ):
            app.scan("binary", ["192.0.2.1"], [(base, base + 100)], 1)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "report.csv"
        self.arguments = [
            "--ip",
            "192.0.2.1",
            "--window",
            "2026-10-01 09:00",
            "2026-10-01 09:06",
            "--output",
            str(self.output),
        ]

    def run_main(self, arguments):
        with contextlib.redirect_stderr(io.StringIO()):
            return app.main(arguments)

    def test_dry_run_does_not_execute_or_write(self):
        with (
            patch.object(app.subprocess, "run") as run,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(self.run_main(self.arguments + ["--dry-run"]), 0)
        run.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertEqual(len(output.getvalue().splitlines()), 3)

    def test_invalid_arguments(self):
        for extra in (
            ["--ip", "192.0.2.1;evil"],
            ["--timeout", "0"],
            ["--timeout", "nan"],
            ["--timeout", "inf"],
            ["--window", "bad", "bad"],
            ["--window", "2026-10-01 10:00", "2026-10-01 09:00"],
        ):
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as error:
                self.run_main(self.arguments + extra)
            self.assertEqual(error.exception.code, 2)

    def test_late_query_failure_preserves_existing_output(self):
        self.output.write_text("previous report", encoding="utf-8")
        first = subprocess.CompletedProcess(
            [], 0, legacy(timestamp=str(app.parse_time("2026-10-01 09:01"))), ""
        )
        failure = subprocess.CompletedProcess([], 4, "", "failed")
        with patch.object(app.subprocess, "run", side_effect=[first, failure]):
            self.assertEqual(self.run_main(self.arguments), 1)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "previous report")
        self.assertEqual(list(self.output.parent.glob("*.tmp")), [])

    def test_failed_replace_cleans_temporary_file(self):
        self.output.write_text("previous report", encoding="utf-8")
        with (
            patch.object(app, "scan", return_value=[]),
            patch.object(app.os, "replace", side_effect=OSError("locked")),
        ):
            self.assertEqual(self.run_main(self.arguments), 1)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "previous report")
        self.assertEqual(list(self.output.parent.glob("*.tmp")), [])

    def test_partial_collection_preserves_successes_and_marks_gaps(self):
        first = subprocess.CompletedProcess(
            [], 0, legacy(timestamp=str(app.parse_time("2026-10-01 09:01"))), ""
        )
        failure = subprocess.CompletedProcess([], 0, "ACTUAL==> missing logs", "")
        with patch.object(app.subprocess, "run", side_effect=[first, failure, first]):
            self.assertEqual(
                self.run_main(self.arguments + ["--format", "json", "--allow-partial"]),
                3,
            )
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertFalse(report["complete"])
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(len(report["failed_queries"]), 1)
        self.assertEqual(report["failed_queries"][0]["ip"], "192.0.2.1")

    def test_partial_csv_is_rejected(self):
        with self.assertRaises(SystemExit) as error:
            self.run_main(self.arguments + ["--allow-partial"])
        self.assertEqual(error.exception.code, 2)

    def test_csv_quotes_addresses_and_empty_output(self):
        rows = [{"email": '"last,first"@example.com'}]
        with patch.object(app, "scan", return_value=rows):
            self.assertEqual(self.run_main(self.arguments), 0)
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.reader(stream)), [['"last,first"@example.com']])
        with patch.object(app, "scan", return_value=[]):
            self.assertEqual(self.run_main(self.arguments), 0)
        self.assertEqual(self.output.read_bytes(), b"")

    def test_json_stdout_retains_evidence(self):
        rows = [
            {
                "ip": "192.0.2.1",
                "email": "person@example.com",
                "timestamp": "100.01",
                "raw": legacy(),
            }
        ]
        with (
            patch.object(app, "scan", return_value=rows),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                self.run_main(self.arguments + ["--format", "json", "--output", "-"]), 0
            )
        report = json.loads(output.getvalue())
        self.assertEqual(report["deliveries"], rows)
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(report["delivery_count"], 1)

    def test_missing_executable_and_interrupt(self):
        for error, code in (
            (FileNotFoundError("missing"), 1),
            (KeyboardInterrupt(), 130),
        ):
            with patch.object(app.subprocess, "run", side_effect=error):
                self.assertEqual(self.run_main(self.arguments), code)
            self.assertFalse(self.output.exists())

    def test_interactive_last_hour_rolls_into_next_day(self):
        with patch(
            "builtins.input", side_effect=["01/10/2026", "192.0.2.1", "23", "23"]
        ):
            args = app.interactive_args()
        self.assertEqual(args[-2:], ["2026-10-01 23:00:00", "2026-10-02 00:00:00"])

    def test_no_arguments_in_noninteractive_session(self):
        with patch.object(app.sys.stdin, "isatty", return_value=False):
            self.assertEqual(self.run_main([]), 2)

    def test_real_child_process_without_greenarrow(self):
        fake = Path(self.temporary.name) / "fake_greenarrow.py"
        fake.write_text(
            "import sys\nfrom datetime import datetime\n"
            "anchor = int(datetime.strptime(sys.argv[2], '%d/%m/%Y %H:%M:%S').timestamp())\n"
            "print(f'email=<person@example.com> smtp_result_time=<{anchor}> smtp_result=<accepted> sendid=<one>')\n",
            encoding="utf-8",
        )
        real_run = subprocess.run

        def run_python(command, **kwargs):
            return real_run([sys.executable, str(fake), *command[1:]], **kwargs)

        with patch.object(app.subprocess, "run", side_effect=run_python):
            self.assertEqual(self.run_main(self.arguments + ["--format", "json"]), 0)
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(
            report["delivery_count"], 2
        )  # The third anchor is beyond the exclusive end.


if __name__ == "__main__":
    unittest.main()
