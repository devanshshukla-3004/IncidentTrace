# IncidentTrace

**Cross-platform incident timeline reconstruction and event correlation** for Windows and Linux security-log exports. IncidentTrace normalizes records from CSV, JSON, JSONL/NDJSON and common RFC3164-style syslog text, orders them chronologically, and creates explainable investigation leads from simple correlation rules.

## Features
- Multi-format ingestion with per-line parse errors.
- Common event schema: timestamp, host, user, source IP, event ID/type, severity, message, source file and original raw fields.
- UTC timestamp normalization and chronological timeline.
- `AUTH-001`: repeated authentication failures for the same host/user/source IP in a configurable time window.
- `AUTH-002`: authentication failures followed by success for the same host/user/source IP.
- `PRIV-001`: keyword-based potential privilege/group change indicator.
- JSON investigation report with timeline, leads, evidence snippets, parse errors and limitations; optional timeline CSV.
- Configurable threshold/window; no paid APIs or third-party runtime dependencies.

## Quick start
Python 3.10+ recommended.

```bash
python incidenttrace.py samples/auth_events.jsonl --output report.json
python incidenttrace.py exported-windows-events.csv linux-auth.log --output report.json --threshold 5 --window 10
python incidenttrace.py samples/auth_events.jsonl --output timeline.csv
python -m unittest discover -s tests -v
```

Windows PowerShell supports the same commands with `py` or `python`. On Linux/macOS, use `python3` if needed.

## Windows and Linux inputs
- **Windows:** Export relevant events from Event Viewer as CSV; CSV is supported directly. Convert XML exports to CSV/JSON before import. Native binary `.evtx` parsing is not included, avoiding external dependencies.
- **Linux:** Common auth/syslog lines (for example from `/var/log/auth.log` or `/var/log/secure`) are supported on a best-effort basis. JSONL/CSV exports from journald or other collectors can also be imported.
- Import only logs you are authorized to access. Redact secrets and personal data before sharing reports.

## Correlation rules are not verdicts
These heuristics are not proof of compromise. Shared NAT addresses, service accounts, clock skew, incomplete logs and benign automation can create misleading correlations. Naive timestamps are treated as UTC; verify source timezone and time synchronization. Preserve original logs for evidentiary purposes; this tool does not guarantee forensic chain of custody.

## Layout
- `incidenttrace.py` — CLI, parsers, normalization, correlation, reports
- `tests/` — standard-library unit tests
- `samples/` — synthetic sample events using documentation-only IPs
- `.github/workflows/tests.yml` — CI workflow

## Difference from WebLogHunter
WebLogHunter inspects web access logs for suspicious request patterns. IncidentTrace reconstructs timelines across general security events and correlates authentication/privilege-related activity. It does not query threat feeds, modify systems, or attempt exploitation.
