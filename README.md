# GreenArrow Spamtrap Review Collector

Search retained GreenArrow delivery logs across **multiple time ranges and sending IPs**, then export both candidate addresses and the delivery evidence behind them. Python 3.10+, standard library only.

GreenArrow's [`hvmail_get_possible_spamtrap_hits`](https://www.greenarrowemail.com/docs/greenarrow-engine/Reporting/hvmail-get-possible-spamtrap-hits-Command) returns deliveries in a fixed window around one timestamp: 60 seconds before through 120 seconds after. This collector combines those lookups into longer searches, including overnight and multi-day ranges.

**Results are review candidates.** The native command selects deliveries by IP and time; an address appearing in the results is not proof that it is a spamtrap.

## Built for investigations

| Need | What this gives you |
| --- | --- |
| Search beyond one timestamp | Repeatable ranges covering minutes, days, or separated incidents |
| Follow multiple sending IPs | One run across all selected IPs and ranges |
| Keep the evidence | JSON retains every distinct returned delivery line and its source IP |
| Review a clean address list | Sorted, deduplicated CSV without losing the detailed JSON option |
| Salvage available data | Explicit partial reports identify every failed lookup |
| Run it reliably | Validated inputs, dry runs, progress, timeouts, and atomic report replacement |

**For the richest collection, choose `--format json`.** CSV is the compact address export; JSON is the investigation record.

## Quick start

Run on the Linux server that has GreenArrow installed and can read its delivery logs:

**Replace every example IP and date below.** `192.0.2.10` and `192.0.2.11` are documentation addresses, not your server's sending IPs. Use IPs configured in GreenArrow, or use `--all-ips` to discover them automatically.

```bash
git clone https://github.com/riotrequest/filter_emails.py.git
cd filter_emails.py
mkdir -p reports

# Keep delivery evidence, rather than only addresses.
python3 filter_emails.py \
  --ip 192.0.2.10 \
  --window "2026-10-01 00:00" "2026-10-03 00:00" \
  --format json --output reports/investigation.json --verbose
```

Use the server's local timezone, matching the native command. Times accept `YYYY-MM-DD HH:MM[:SS]`, an ISO `T` separator, or `DD/MM/YYYY HH:MM[:SS]`. Every window includes its start and excludes its end. For an entire day, end at midnight the following day. Ambiguous or nonexistent local times during daylight-saving changes are rejected; a range whose query anchors encounter an ambiguous time also fails.

No-argument execution in a terminal retains the original date/IP/hour prompts. The prompted end hour is inclusive: `9` through `10` scans `[09:00, 11:00)`. Noninteractive execution requires arguments.

## Collect across incidents and IPs

```bash
python3 filter_emails.py \
  --ip 192.0.2.10 --ip 192.0.2.11 \
  --window "2026-10-01 09:00" "2026-10-01 12:00" \
  --window "2026-10-04 18:00" "2026-10-05 02:00" \
  --format json --output reports/multiple-incidents.json
```

Every IP is scanned against every window. Duplicate IPs and overlapping or adjacent windows are combined. Commands run sequentially, with a one-second overlap between three-minute lookups to avoid depending on endpoint inclusivity. A one-hour range uses 21 commands per IP instead of the original 60. Returned delivery timestamps are filtered to the exact requested ranges.

## Collect every configured sending IP efficiently

```bash
python3 filter_emails.py --all-ips \
  --window "2026-10-01 00:00" "2026-10-02 00:00" \
  --allow-partial --format json --output reports/all-ips.json --verbose
```

`--all-ips` discovers configured IPs and relevant send summaries through GreenArrow's installed Perl helpers. It reads PostgreSQL metadata in a read-only transaction and opens each SQLite summary in read-only mode. Each relevant summary is visited once across all IPs and windows, avoiding thousands of repeated native lookups. This mode requires access to `/var/hvmail/libexec/perl`, `/var/hvmail/perllib`, and GreenArrow's send-summary files; run as the account with those permissions.

This mode uses GreenArrow's internal summary schema and must be revalidated after GreenArrow upgrades. It preserves the native command's **last SMTP result per message** semantics; it does not reconstruct every retry or earlier delivery attempt. Use `hvmail_report` when you need the complete retained attempt history.

If mail goes through SMTP relay providers, add `--include-relays`. Relay routes have different IDs from direct sending IPs; the native IP lookup does not include those routes. Relay records identify their `outmtaid`, `route_type`, and `relay_server`. Their `ip` is the local source address of the connection to the relay (or `null` if no source address is configured), **not the relay provider's eventual delivery IP**. This field cannot tell you which provider egress IP delivered the message. `--include-relays` requires `--all-ips`.

```bash
python3 filter_emails.py --all-ips --include-relays \
  --window "2026-10-01 00:00" "2026-10-02 00:00" \
  --allow-partial --format json --output reports/all-routes.json --verbose
```

Missing or unreadable summaries fail the scan by default. With `--allow-partial`, readable evidence is saved, missing files are listed in `failed_queries`, `complete` is false, and the process exits 3. In this mode, failed entries identify a summary file and SendID rather than a timestamp/IP lookup. `--dry-run` prints the discovered IPs and summary paths; discovery still requires GreenArrow access. `--timeout` applies to inventory discovery; SQLite reads use the standard lock timeout.

## Output

| Format | Contents |
| --- | --- |
| `--format json` | Unique addresses, all distinct returned delivery records, source sending IP, exact epoch timestamp as a string, original report line, requested coverage, and completeness status |
| `--format csv` (default) | Sorted unique addresses, one per CSV row, without a header; defaults to `email_addresses.csv` |

JSON retains original report lines so fields such as SendID, delivery result, SMTP response, and any additional fields present in the native output survive collection. Exact duplicate lines for the same IP are removed; different lines for the same recipient remain separate records. Address spelling and case are preserved. This does not infer separate events from byte-identical native records.

A JSON report includes the following fields (abridged example using synthetic data):

```json
{
  "candidate_count": 1,
  "emails": ["person@example.com"],
  "ips": ["192.0.2.10"],
  "delivery_count": 1,
  "deliveries": [
    {
      "ip": "192.0.2.10",
      "email": "person@example.com",
      "timestamp": "1790845259.1234",
      "raw": "email=<person@example.com> smtp_result_time=<1790845259.1234> smtp_result=<accepted> smtp_result_message=<> sendid=<example-send>"
    }
  ],
  "complete": true,
  "failed_queries": [],
  "classification": "review_candidates_not_confirmed_spamtraps"
}
```

The full report also includes `windows` with inclusive start and exclusive end epoch values. Delivery timestamps remain strings to preserve the precision of the native log.

CSV example:

```bash
python3 filter_emails.py --ip 192.0.2.10 \
  --window "2026-10-01 09:00" "2026-10-01 10:00" \
  --output reports/candidates.csv
```

Use `--output -` for stdout. Progress and status messages go to stderr, keeping JSON and CSV pipelines clean. CSV uses proper quoting for addresses containing commas or quotes. Treat exported CSV as data when importing into a spreadsheet.

## Preview, failures, and partial evidence

```bash
# Print planned commands without requiring GreenArrow or creating an output file.
python3 filter_emails.py --ip 192.0.2.10 \
  --window "2026-10-01 09:00" "2026-10-01 10:00" --dry-run

# Retain successful lookups if some requested logs are unavailable.
python3 filter_emails.py --ip 192.0.2.10 \
  --window "2026-10-01 00:00" "2026-10-03 00:00" \
  --allow-partial --format json --output reports/partial-evidence.json
```

By default, a failed command, timeout, unrecognized stderr diagnostic, missing-log notice, invalid encoding, or unknown report format aborts the scan. Known native progress banners, SendID progress, and summary filenames on stderr are accepted; missing-summary warnings remain errors. An existing output file is replaced atomically only after all queries and serialization succeed. Successful empty scans produce an empty CSV or a JSON report with zero counts.

`--allow-partial` continues after failed queries, retains successful evidence, sets `complete: false`, lists every failed query with its IP, timestamp, and error, and exits **3**. It requires JSON so a list of addresses cannot conceal missing coverage. It can replace an existing report with an explicitly incomplete report; use a separate output name if preserving earlier evidence. Cancellation still aborts without saving the current scan.

| Exit status | Meaning |
| --- | --- |
| `0` | Scan succeeded, or dry run completed |
| `1` | Execution, parsing, time conversion, or output error |
| `2` | Invalid or missing arguments |
| `3` | Explicitly requested partial report saved with failed queries |
| `130` | Cancelled |

Use `--timeout 300` to change the default 120 seconds per command. `--command /custom/path/hvmail_get_possible_spamtrap_hits` changes the executable path; it accepts a path, not a shell command. Run `python3 filter_emails.py --help` for all options.

## Install a CLI command

Installation is optional; the standalone script has no third-party runtime dependencies.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
greenarrow-spamtrap-review --help
```

## Coverage limits and GreenArrow references

- Longer searches cannot recover logs GreenArrow has already rotated away. The [`hvmail_report` documentation](https://www.greenarrowemail.com/docs/greenarrow-engine/Reporting/hvmail-report-Command) explains retention and increasing delivery-log disk allocation. This collector does not change server configuration.
- For broader delivery investigations, native `hvmail_report -q all --start ... --end ... --processed-logfile` supports arbitrary ranges and all queues, including failures and retries, with filters such as `--mtaid` and `--sendid`. Those selectors differ from this collector's sending-IP lookup; the command's documented options do not include a sending-IP filter.
- The parser accepts the [possible-spamtrap command's legacy example](https://www.greenarrowemail.com/docs/greenarrow-engine/Reporting/hvmail-get-possible-spamtrap-hits-Command), plus the current [tab-separated and human-readable processed log formats](https://www.greenarrowemail.com/docs/greenarrow-engine/Reporting/Delivery-Event-Processed-Logfile-Format). New, unrecognized output fails visibly instead of silently dropping records.
- Queries buffer native output and keep distinct delivery evidence in memory until export. For very large investigations, split work into smaller windows and separate JSON files. No arbitrary scan-duration or result-count cap is imposed.

The integration follows the official GreenArrow documentation reviewed on 2026-10-15. The native stderr behavior and summary schema were also checked on a live GreenArrow installation. Automated checks use synthetic reports, read-only SQLite fixtures, and a fake child process; validate compatibility on your own GreenArrow version. Report files contain recipient data; `reports/` is ignored by Git and new files use private POSIX temporary-file permissions.

## Development

```bash
python -m unittest discover -s tests -v
```

CI checks Python 3.10–3.14 on Linux and Python 3.14 on Windows, including installation and the CLI entry point. The Linux runs also exercise daylight-saving transitions. Tests require no GreenArrow installation, mail logs, or network access.

CI also runs Gitleaks against the complete fetched Git history. The scanner download is pinned and checksum-verified; findings are redacted. Local `.env` files and common private-key containers are ignored by Git.
