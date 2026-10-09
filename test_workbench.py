import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from workbench import markdown, timestamp, triage

NOW = timestamp("2026-10-08T12:00:00Z")


def finding(**updates):
    result = {"SchemaVersion": "2018-10-08", "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
              "Id": "example-1", "AwsAccountId": "111111111111", "GeneratorId": "security-control/EC2.19",
              "CreatedAt": "2026-09-01T00:00:00Z", "UpdatedAt": "2026-10-07T00:00:00Z",
              "LastObservedAt": "2026-10-07T00:00:00Z", "Title": "Synthetic SSH exposure",
              "Description": "Synthetic portfolio fixture; not an actual account finding.",
              "Types": ["Software and Configuration Checks"], "Severity": {"Label": "HIGH"},
              "Resources": [{"Id": "synthetic-sg", "Type": "AwsEc2SecurityGroup"}],
              "Workflow": {"Status": "NEW"}, "RecordState": "ACTIVE"}
    result.update(updates)
    return result


class TriageTests(unittest.TestCase):
    def report(self, records, notes=None):
        return triage({"Findings": records}, notes or [], NOW)

    def test_snapshot_dedup_keeps_latest_with_provenance(self):
        old = finding(UpdatedAt="2026-09-30T00:00:00Z", Title="old")
        r = self.report([old, finding(), finding()])
        self.assertEqual(r["summary"]["duplicate_records"], 2)
        self.assertEqual(r["findings"][0]["title"], "Synthetic SSH exposure")
        self.assertEqual(r["findings"][0]["source_indices"], [0, 1, 2])

    def test_same_id_different_product_never_merges(self):
        r = self.report([finding(), finding(ProductArn="another-product")])
        self.assertEqual(len(r["findings"]), 2)

    def test_same_cve_and_resource_are_not_duplicate_identity(self):
        a = finding(Vulnerabilities=[{"Id": "CVE-2099-0001"}])
        b = copy.deepcopy(a); b["Id"] = "other-finding"
        self.assertEqual(len(self.report([a, b])["findings"]), 2)

    def test_equal_time_conflict_is_visible_and_order_independent(self):
        a, b = finding(), finding(Workflow={"Status": "RESOLVED"})
        left, right = self.report([a, b]), self.report([b, a])
        self.assertIn("conflicting_latest_snapshots", left["findings"][0]["quality_flags"])
        self.assertEqual(left, right)

    def test_recent_provider_update_does_not_refresh_old_observation(self):
        row = self.report([finding(LastObservedAt="2026-09-01T00:00:00Z")])["findings"][0]
        self.assertIn("stale_observation", row["quality_flags"])

    def test_missing_observation_is_unknown(self):
        f = finding(); del f["LastObservedAt"]
        self.assertIn("observation_time_missing", self.report([f])["findings"][0]["quality_flags"])

    def test_future_dates_do_not_disappear(self):
        row = self.report([finding(UpdatedAt="2027-01-01T00:00:00Z", LastObservedAt="2027-01-01T00:00:00Z")])["findings"][0]
        self.assertIn("future_timestamp", row["quality_flags"])
        self.assertIn("future_observation", row["quality_flags"])

    def test_expired_suppression_returns_to_action_queue(self):
        f = finding(Workflow={"Status": "SUPPRESSED"})
        note = {"ProductArn": f["ProductArn"], "Id": f["Id"], "owner": "platform",
                "exception": {"expires_at": "2026-10-08T12:00:00Z", "reason": "Synthetic exception", "ticket": "DEMO-1"}}
        row = self.report([f], [note])["findings"][0]
        self.assertEqual(row["exception_state"], "expired")
        self.assertEqual(row["priority"], "urgent_review")
        note["exception"]["expires_at"] = "2026-10-09T00:00:00Z"
        row = self.report([f], [note])["findings"][0]
        self.assertFalse(row["overdue"])

    def test_missing_exception_evidence_does_not_validate_suppression(self):
        f = finding(Workflow={"Status": "SUPPRESSED"})
        note = {"ProductArn": f["ProductArn"], "Id": f["Id"], "exception": {"expires_at": "2027-01-01T00:00:00Z"}}
        self.assertEqual(self.report([f], [note])["findings"][0]["exception_state"], "invalid")

    def test_invalid_record_does_not_drop_valid_ones(self):
        r = self.report([finding(), {}, None, finding(Severity=None)])
        self.assertEqual(r["summary"]["invalid_records"], 3)
        self.assertEqual(r["summary"]["unique_findings"], 1)

    def test_resolved_and_archived_are_not_claimed_overdue(self):
        for f in [finding(Workflow={"Status": "RESOLVED"}), finding(RecordState="ARCHIVED")]:
            self.assertFalse(self.report([f])["findings"][0]["overdue"])

    def test_ambiguous_annotations_rejected(self):
        a = {"ProductArn": "x", "Id": "y"}
        with self.assertRaises(ValueError): self.report([], [a, a])

    def test_html_and_table_markup_escaped(self):
        output = markdown(self.report([finding(Title="<img src=x>|fake\nrow")]))
        self.assertNotIn("<img", output)
        self.assertIn("&#124;", output)

    def test_timezone_required(self):
        with self.assertRaises(ValueError): timestamp("2026-10-08")

    def test_markdown_image_syntax_is_escaped(self):
        self.assertNotIn("![", markdown(self.report([finding(Title="![image](https://example.com)")])))

    def test_fixture_cli_reproducible(self):
        cmd = [sys.executable, "workbench.py", "examples/findings.json", "--annotations", "examples/annotations.json", "--as-of", "2026-10-08T12:00:00Z"]
        first = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        self.assertEqual(first, subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)
        self.assertEqual(json.loads(first), json.loads(Path("examples/report.json").read_text()))


if __name__ == "__main__": unittest.main()
