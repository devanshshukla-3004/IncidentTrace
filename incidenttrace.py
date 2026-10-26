#!/usr/bin/env python3
"""IncidentTrace: normalize security events and correlate investigation leads."""
from __future__ import annotations
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "date", "event_time", "@timestamp"),
    "host": ("host", "hostname", "computer", "machine", "device"),
    "user": ("user", "username", "account", "account_name", "subjectusername", "targetusername"),
    "source_ip": ("source_ip", "src_ip", "ip", "client_ip", "remote_addr", "sourceaddress", "ipaddress"),
    "event_id": ("event_id", "eventid", "id", "event_code", "code"),
    "event_type": ("event_type", "type", "action", "event", "category", "eventtype"),
    "message": ("message", "msg", "description", "details", "raw", "event_data"),
    "severity": ("severity", "level", "priority"),
}
FAILED_TERMS = ("failed password", "authentication failure", "login failed", "failed logon", "logon failure", "invalid user", "authentication failed")
SUCCESS_TERMS = ("accepted password", "login successful", "successful logon", "logon success", "logged in", "authentication success", "user logged in")
PRIV_TERMS = ("sudo", "privilege escalation", "special privileges", "added to administrators", "added to sudo", "usermod", "groupadd")

def parse_timestamp(value: Any) -> str:
    """Return UTC ISO-8601; naive values are interpreted as UTC."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("event is missing a timestamp")
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
            try:
                dt = datetime.strptime(text, fmt)
                if fmt.startswith("%b"):
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                break
            except ValueError:
                continue
        if dt is None:
            raise ValueError(f"unsupported timestamp: {text}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")

def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())

def normalize_record(record: dict[str, Any], source: str = "") -> dict[str, Any]:
    lookup = {_key(k): v for k, v in record.items()}
    normalized = {}
    for field, aliases in ALIASES.items():
        value = next((lookup[_key(alias)] for alias in aliases if _key(alias) in lookup and lookup[_key(alias)] not in (None, "")), None)
        normalized[field] = str(value).strip() if value is not None else ""
    normalized["timestamp"] = parse_timestamp(normalized["timestamp"])
    for field, default in (("host", "unknown"), ("user", "unknown"), ("source_ip", "unknown"), ("event_id", "unknown"), ("event_type", "unknown"), ("severity", "unknown")):
        normalized[field] = normalized[field] or default
    normalized["message"] = normalized["message"] or normalized["event_type"] or "(no message supplied)"
    normalized["source_file"] = source
    normalized["raw"] = {str(k): v for k, v in record.items()}
    return normalized

def parse_syslog_line(line: str) -> dict[str, str] | None:
    """Best-effort parser for common RFC3164-style syslog/auth lines."""
    match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$", line.strip())
    if not match:
        return None
    timestamp, host, process, message = match.groups()
    ip_match = re.search(r"\b(?:from\s+|rhost=)(\d{1,3}(?:\.\d{1,3}){3})\b", message)
    user_match = re.search(r"(?:for|user[= ])\s*([\w.@$-]+)", message, re.I)
    return {"timestamp": timestamp, "host": host, "event_type": process, "message": message,
            "source_ip": ip_match.group(1) if ip_match else "unknown",
            "user": user_match.group(1) if user_match else "unknown"}

def load_file(path: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    path = Path(path)
    events, errors = [], []
    suffix = path.suffix.lower()
    if suffix in (".jsonl", ".ndjson"):
        with path.open(encoding="utf-8-sig") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip(): continue
                try:
                    obj = json.loads(line)
                    if not isinstance(obj, dict): raise ValueError("JSON line must be an object")
                    events.append(normalize_record(obj, str(path)))
                except (json.JSONDecodeError, ValueError) as exc:
                    errors.append({"source_file": str(path), "line": str(number), "error": str(exc)})
    elif suffix == ".json":
        with path.open(encoding="utf-8-sig") as handle: data = json.load(handle)
        rows = data if isinstance(data, list) else data.get("events", [data]) if isinstance(data, dict) else []
        for number, obj in enumerate(rows, 1):
            try: events.append(normalize_record(obj, str(path)))
            except (ValueError, TypeError) as exc: errors.append({"source_file": str(path), "line": str(number), "error": str(exc)})
    elif suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            for number, obj in enumerate(csv.DictReader(handle), 2):
                try: events.append(normalize_record(obj, str(path)))
                except (ValueError, TypeError) as exc: errors.append({"source_file": str(path), "line": str(number), "error": str(exc)})
    else:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip(): continue
                obj = parse_syslog_line(line)
                if not obj:
                    errors.append({"source_file": str(path), "line": str(number), "error": "unrecognized syslog line"}); continue
                try: events.append(normalize_record(obj, str(path)))
                except ValueError as exc: errors.append({"source_file": str(path), "line": str(number), "error": str(exc)})
    return events, errors

def classify(event: dict[str, Any]) -> str:
    text = " ".join((event.get("message", ""), event.get("event_type", ""), event.get("event_id", ""))).lower()
    if any(term in text for term in FAILED_TERMS): return "auth_failure"
    if any(term in text for term in SUCCESS_TERMS): return "auth_success"
    if any(term in text for term in PRIV_TERMS) or event.get("event_id", "") in {"4672", "4728", "4732", "4756"}: return "privilege_change"
    if "process create" in text or "process creation" in text or (event.get("event_id") in {"4688", "1"} and "process" in text): return "process_creation"
    return "other"

def correlate(events: list[dict[str, Any]], threshold: int = 5, window_minutes: int = 10) -> list[dict[str, Any]]:
    """Create explainable investigation leads, never definitive attack verdicts."""
    ordered = sorted(events, key=lambda e: e["timestamp"])
    leads, failures = [], defaultdict(list)
    for event in ordered:
        kind = classify(event)
        key = (event["host"], event["user"], event["source_ip"])
        if kind == "auth_failure":
            failures[key].append(event)
        elif kind == "auth_success":
            prior = [x for x in failures.get(key, []) if x["timestamp"] <= event["timestamp"] and
                     datetime.fromisoformat(event["timestamp"]) - datetime.fromisoformat(x["timestamp"]) <= timedelta(minutes=window_minutes)]
            if prior:
                evidence = [{"timestamp": x["timestamp"], "message": x["message"], "source_file": x["source_file"]} for x in prior]
                evidence.append({"timestamp": event["timestamp"], "message": event["message"], "source_file": event["source_file"]})
                leads.append({"rule_id": "AUTH-002", "severity": "HIGH", "title": "Authentication failures followed by success",
                    "summary": f"A successful authentication followed {len(prior)} failure event(s) for the same user, host and source IP within {window_minutes} minutes.",
                    "host": event["host"], "user": event["user"], "source_ip": event["source_ip"], "start": prior[0]["timestamp"],
                    "end": event["timestamp"], "evidence_count": len(evidence), "evidence": evidence,
                    "caveat": "Correlation lead only; verify identity, shared IPs and surrounding context."})
        elif kind == "privilege_change":
            leads.append({"rule_id": "PRIV-001", "severity": "MEDIUM", "title": "Potential privilege or group change",
                "summary": "Event text matches a privilege-change indicator; validate it against authorized activity.",
                "host": event["host"], "user": event["user"], "source_ip": event["source_ip"],
                "start": event["timestamp"], "end": event["timestamp"], "evidence_count": 1,
                "evidence": [{"timestamp": event["timestamp"], "message": event["message"], "source_file": event["source_file"]}],
                "caveat": "Keyword-based heuristic; review event text and platform-specific IDs."})
    for (host, user, ip), group in failures.items():
        for index, first in enumerate(group):
            start = datetime.fromisoformat(first["timestamp"])
            subset = [x for x in group[index:] if datetime.fromisoformat(x["timestamp"]) - start <= timedelta(minutes=window_minutes)]
            if len(subset) >= threshold:
                leads.append({"rule_id": "AUTH-001", "severity": "HIGH", "title": "Repeated authentication failures",
                    "summary": f"{len(subset)} failed authentication events for the same user, host and source IP within {window_minutes} minutes.",
                    "host": host, "user": user, "source_ip": ip, "start": subset[0]["timestamp"], "end": subset[-1]["timestamp"],
                    "evidence_count": len(subset), "evidence": [{"timestamp": x["timestamp"], "message": x["message"], "source_file": x["source_file"]} for x in subset],
                    "caveat": "Could reflect mistyped credentials, automation or an attack; validate before concluding."})
                break
    return sorted(leads, key=lambda item: (item["start"], item["rule_id"]))

def analyze(events: list[dict[str, Any]], errors: list[dict[str, str]], threshold: int = 5, window_minutes: int = 10) -> dict[str, Any]:
    timeline = sorted(events, key=lambda e: e["timestamp"])
    leads = correlate(timeline, threshold, window_minutes)
    return {"tool": "IncidentTrace", "schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": {"events_loaded": len(timeline), "parse_errors": len(errors), "correlation_leads": len(leads)},
            "timeline": timeline, "correlation_leads": leads, "parse_errors": errors,
            "limitations": ["Correlations are investigation leads, not proof of malicious activity.",
                "Timestamp-naive values are interpreted as UTC; verify source timezone before cross-host conclusions.",
                "Native Windows EVTX parsing is not included; export to supported CSV/JSON first."]}

def write_report(report: dict[str, Any], output: str) -> None:
    path = Path(output)
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as handle:
            fields = ["timestamp", "host", "user", "source_ip", "event_id", "event_type", "severity", "message", "source_file"]
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader(); writer.writerows(report["timeline"])
    else:
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Normalize security event exports and correlate incident leads")
    parser.add_argument("inputs", nargs="+", help="CSV, JSON, JSONL/NDJSON, or syslog text files")
    parser.add_argument("--output", default="incidenttrace-report.json", help="Output JSON report or timeline CSV")
    parser.add_argument("--threshold", type=int, default=5, help="Failed auth events to flag (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="Correlation window in minutes (default: 10)")
    args = parser.parse_args(argv)
    if args.threshold < 2 or args.window < 1: parser.error("--threshold must be >= 2 and --window must be >= 1")
    events, errors = [], []
    for filename in args.inputs:
        try:
            loaded, failed = load_file(filename); events.extend(loaded); errors.extend(failed)
        except (OSError, json.JSONDecodeError, UnicodeError) as exc:
            errors.append({"source_file": filename, "line": "", "error": str(exc)})
    if not events:
        print("No valid events loaded. Check input formats and parse_errors.", file=sys.stderr); return 2
    report = analyze(events, errors, args.threshold, args.window)
    try: write_report(report, args.output)
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr); return 2
    print(f"Events loaded: {report['summary']['events_loaded']}")
    print(f"Correlation leads: {report['summary']['correlation_leads']}")
    print(f"Parse errors: {report['summary']['parse_errors']}")
    for lead in report["correlation_leads"]:
        print(f"[{lead['severity']}] {lead['rule_id']} {lead['title']} — {lead['summary']}")
    print(f"Report written to: {args.output}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
