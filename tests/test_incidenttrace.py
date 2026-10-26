import tempfile
import unittest
from pathlib import Path
from incidenttrace import analyze, classify, load_file, normalize_record, parse_syslog_line

class IncidentTraceTests(unittest.TestCase):
    def test_normalizes_aliases_and_utc(self):
        event = normalize_record({"Time": "2025-01-01T12:00:00+02:00", "Computer": "host1", "Message": "hello"})
        self.assertEqual(event["timestamp"], "2025-01-01T10:00:00+00:00")
        self.assertEqual(event["host"], "host1")

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(ValueError): normalize_record({"message": "missing timestamp"})

    def test_syslog_parser_extracts_host_ip_and_user(self):
        parsed = parse_syslog_line("Oct 27 10:10:01 web01 sshd[123]: Failed password for alice from 192.0.2.5 port 22 ssh2")
        self.assertEqual(parsed["host"], "web01")
        self.assertEqual(parsed["source_ip"], "192.0.2.5")
        self.assertEqual(parsed["user"], "alice")

    def test_jsonl_load_records_parse_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"timestamp":"2025-01-01T00:00:00Z","message":"ok"}\nnot-json\n', encoding="utf-8")
            events, errors = load_file(path)
            self.assertEqual(len(events), 1); self.assertEqual(len(errors), 1)

    def test_failure_burst_correlated(self):
        events = [normalize_record({"timestamp": f"2025-01-01T00:0{minute}:00Z", "host": "h", "user": "alice", "source_ip": "192.0.2.8", "message": "Failed password"}) for minute in range(5)]
        self.assertTrue(any(x["rule_id"] == "AUTH-001" for x in analyze(events, [], threshold=5)["correlation_leads"]))

    def test_failure_then_success_correlated(self):
        records = [
            {"timestamp":"2025-01-01T00:00:00Z", "host":"h", "user":"bob", "source_ip":"192.0.2.4", "message":"Failed password"},
            {"timestamp":"2025-01-01T00:02:00Z", "host":"h", "user":"bob", "source_ip":"192.0.2.4", "message":"Accepted password"}]
        events = [normalize_record(x) for x in records]
        self.assertTrue(any(x["rule_id"] == "AUTH-002" for x in analyze(events, [])["correlation_leads"]))

    def test_privilege_change_flagged(self):
        event = normalize_record({"timestamp":"2025-01-01T00:00:00Z", "message":"user added to sudo group"})
        self.assertEqual(classify(event), "privilege_change")
        self.assertTrue(any(x["rule_id"] == "PRIV-001" for x in analyze([event], [])["correlation_leads"]))

    def test_windows_group_membership_event_id(self):
        event = normalize_record({"timestamp":"2025-01-01T00:00:00Z", "event_id":"4732", "message":"A member was added to a security-enabled local group"})
        self.assertEqual(classify(event), "privilege_change")
        self.assertTrue(any(x["rule_id"] == "PRIV-001" for x in analyze([event], [])["correlation_leads"]))

    def test_timeline_sorted(self):
        events = [normalize_record({"timestamp":"2025-01-01T00:02:00Z","message":"later"}), normalize_record({"timestamp":"2025-01-01T00:01:00Z","message":"earlier"})]
        self.assertEqual(analyze(events, [])["timeline"][0]["message"], "earlier")

if __name__ == "__main__": unittest.main(verbosity=2)
