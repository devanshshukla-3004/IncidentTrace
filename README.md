# IncidentTrace

<p align="center">
  <strong>Cross-platform security event timeline reconstruction and correlation</strong><br />
  Turn scattered Windows and Linux log exports into a chronological investigation timeline with explainable detection leads.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime dependencies-none-2ea44f" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey" />
  <img alt="Project" src="https://img.shields.io/badge/100%20Days%20of%20Cybersecurity-Day%2022-6f42c1" />
</p>

IncidentTrace is a lightweight, local-first Python CLI for security analysts, students, and blue-team learners. It ingests supported log exports, normalizes common event fields, sorts events by time, and correlates authentication and privilege-related activity into investigation leads with supporting evidence.

It uses Python's standard library only. No paid APIs, external services, or third-party runtime packages are required.

> **Important:** IncidentTrace is a triage and investigation aid—not a SIEM, forensic acquisition tool, or definitive compromise detector. Its correlation rules produce leads that must be validated against source logs and operational context.

## Contents

- [Why IncidentTrace?](#why-incidenttrace)
- [Features](#features)
- [How it works](#how-it-works)
- [Detection rules](#detection-rules)
- [Supported inputs](#supported-inputs)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Output](#output)
- [Run the tests](#run-the-tests)
- [Project structure](#project-structure)
- [Limitations and safe use](#limitations-and-safe-use)
- [Roadmap](#roadmap)
- [Related challenge project](#related-challenge-project)

## Why IncidentTrace?

Security investigations often involve multiple log sources with different field names and timestamp formats. Analysts need to establish what happened, in what order, and which events may be related.

IncidentTrace provides a small, transparent workflow to:

- normalize records into a common event structure;
- reconstruct a chronological timeline;
- flag repeated authentication failures;
- identify a successful authentication shortly after failures for the same host, account, and source IP;
- highlight potential privilege or group changes; and
- export the timeline and correlation evidence for further review.

## Features

- **Multiple input formats:** CSV, JSON, JSONL/NDJSON, and best-effort RFC3164-style syslog text.
- **Field normalization:** timestamp, host, user, source IP, event ID, event type, severity, message, source file, and original fields.
- **Time normalization:** timestamps are converted to UTC ISO 8601 and events are sorted chronologically.
- **Explainable correlation:** every lead includes a rule ID, summary, affected host/account/source IP, time range, evidence snippets, and a caveat.
- **Configurable analysis:** adjust the failed-login threshold and correlation window from the command line.
- **Useful reporting:** structured JSON report or a CSV timeline, plus parse-error reporting.
- **Local-first by design:** input files are processed locally; no telemetry or network service is required by the tool.
- **No third-party runtime dependencies:** built with the Python standard library.

## How it works

1. **Ingest** supported log files.
2. **Normalize** recognized fields into a consistent event schema.
3. **Validate and report** records that cannot be parsed, without silently treating them as valid events.
4. **Build a timeline** sorted by normalized UTC timestamp.
5. **Correlate events** using documented heuristic rules.
6. **Write a report** containing the timeline, investigation leads, evidence, parse errors, and limitations.

## Detection rules

| Rule ID | What it flags | Default behavior |
| --- | --- | --- |
| `AUTH-001` | Repeated authentication failures | Flags a burst of failed authentication events for the same host, user, and source IP within the configured window. Default threshold: 5 events in 10 minutes. |
| `AUTH-002` | Failures followed by success | Flags a successful authentication when one or more matching failures occurred within the configured time window. |
| `PRIV-001` | Potential privilege or group change | Uses keyword indicators and selected Windows event IDs: 4672, 4728, 4732, and 4756. |

These are intentionally simple, readable heuristics. They can miss events when source logs use unfamiliar wording or field names, and can flag benign activity. A rule match is not proof of malicious behavior.

## Supported inputs

| Format | Support | Notes |
| --- | --- | --- |
| CSV | Supported | Uses the header row and recognized field aliases. |
| JSON | Supported | Accepts an object, an object containing an `events` list, or a list of event objects. |
| JSONL / NDJSON | Supported | Reads one JSON event object per non-empty line and records line-level parse errors. |
| Syslog-style text | Best effort | Supports common RFC3164-like lines often found in Linux authentication logs. Parser coverage depends on the log format. |
| Windows Event Viewer CSV export | Supported | Export relevant events to CSV before analysis. |
| Native Windows `.evtx` | Not supported directly | Convert/export to a supported format first; native EVTX parsing is outside the current scope. |

Field names such as `Time`, `Computer`, `Message`, `EventID`, `Username`, and common source-IP variants are mapped through aliases. Unknown or missing optional fields are represented with defaults; a valid timestamp is required for an event to be normalized.

## Requirements

- Python **3.10 or newer** recommended.
- Windows, Linux, or macOS terminal.
- No virtual environment or package installation is necessary for the current version.

Check your Python version:

```bash
python --version
```

On Windows, use `py` if `python` is not on your PATH. On Linux/macOS, use `python3` if needed.

## Quick start

Clone the repository and enter the project directory:

```bash
git clone https://github.com/devanshshukla-3004/IncidentTrace.git
cd IncidentTrace
```

Analyze the included synthetic sample:

```bash
python incidenttrace.py samples/auth_events.jsonl --output report.json
```

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

## Usage

### Analyze one file

```bash
python incidenttrace.py samples/auth_events.jsonl --output report.json
```

### Analyze multiple sources together

```bash
python incidenttrace.py exported-windows-events.csv linux-auth.log --output report.json
```

### Change the authentication-failure threshold and window

For example, flag at least 4 failures within 15 minutes:

```bash
python incidenttrace.py auth-events.jsonl --threshold 4 --window 15 --output report.json
```

The threshold must be at least 2, and the window must be at least 1 minute.

### Export the chronological timeline as CSV

```bash
python incidenttrace.py samples/auth_events.jsonl --output timeline.csv
```

The CSV output contains the normalized timeline fields. For correlation leads and evidence, use JSON output.

### Windows PowerShell examples

```powershell
py .\incidenttrace.py .\samples\auth_events.jsonl --output .\report.json
py -m unittest discover -s tests -v
```

### Linux examples

```bash
python3 incidenttrace.py /var/log/auth.log --output report.json
python3 -m unittest discover -s tests -v
```

Access to system log files may require elevated permissions. Run with the minimum privileges necessary and only analyze logs you are authorized to access.

## Output

JSON output includes:

- `tool` and `schema_version`;
- `generated_at` and a summary of events loaded, parse errors, and correlation leads;
- `timeline`, containing normalized events in chronological order;
- `correlation_leads`, containing rule IDs, severity, summaries, affected entities, time range, evidence, and caveats;
- `parse_errors`, identifying records that could not be processed; and
- `limitations`, which records important interpretation constraints.

A successful run prints the number of events loaded, the number of correlation leads, parse-error count, and output path. If no valid events can be loaded, the CLI exits with a non-zero status and writes a diagnostic to standard error.

Treat reports as potentially sensitive: they may contain usernames, IP addresses, hostnames, and raw log fields.

## Run the tests

The test suite uses Python's built-in `unittest` framework:

```bash
python -m unittest discover -s tests -v
```

A GitHub Actions workflow is included at `.github/workflows/tests.yml` to run the tests on relevant pushes and pull requests. Check the repository's **Actions** tab for the status of the latest remote run.

## Project structure

```text
IncidentTrace/
├── incidenttrace.py
├── README.md
├── samples/
│   └── auth_events.jsonl
├── tests/
│   └── test_incidenttrace.py
└── .github/
    └── workflows/
        └── tests.yml
```

## Limitations and safe use

- **No native EVTX parsing:** export Windows Event Viewer logs to CSV or convert them to supported JSON/CSV first.
- **Best-effort syslog parsing:** non-standard or vendor-specific log formats may not be recognized.
- **Timezone assumptions:** timestamps without timezone information are interpreted as UTC. Verify source timezone and clock synchronization before correlating hosts.
- **Heuristic detections:** benign mistakes, service accounts, shared NAT addresses, automation, incomplete logs, and unfamiliar event wording can cause false positives or false negatives.
- **Not a forensic acquisition tool:** the application does not establish chain of custody, preserve evidence independently, or guarantee forensic integrity. Retain original logs and document your handling process.
- **Sensitive data:** review and redact secrets and personal information before sharing reports or sample logs.
- **Authorized use only:** use IncidentTrace on systems and logs you are permitted to access.

## Roadmap

Potential future improvements:

- native Windows EVTX ingestion;
- additional Windows Security and Linux audit event mappings;
- richer cross-host correlation and configurable rules;
- improved timezone handling and event-source profiles; and
- optional HTML investigation reports.

These are planned possibilities, not features claimed to be implemented in the current version.

## Related challenge project

IncidentTrace is **Day 22** of the *100 Days, 100 Cybersecurity Projects* challenge.

It complements [WebLogHunter](https://github.com/devanshshukla-3004/100-Days-100-Cybersecurity-Projects): WebLogHunter focuses on suspicious patterns in web access logs, while IncidentTrace focuses on normalizing general security events and correlating authentication and privilege-related activity.

---

<p align="center">
  Built by <a href="https://github.com/devanshshukla-3004">Devansh Shukla</a> · <a href="https://github.com/devanshshukla-3004/IncidentTrace">Source code</a>
</p>
