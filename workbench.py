"""Offline ASFF triage with provenance, data-quality checks and expiring exceptions."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
from pathlib import Path
import sys

SLA_DAYS = {"CRITICAL": 3, "HIGH": 7, "MEDIUM": 30, "LOW": 90, "INFORMATIONAL": 90}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def identity(finding):
    values = finding.get("ProductArn"), finding.get("Id")
    if not all(isinstance(v, str) and v.strip() for v in values):
        raise ValueError("ProductArn and Id must be nonempty strings")
    return values


def validate(finding):
    if not isinstance(finding, dict):
        raise ValueError("finding must be an object")
    identity(finding)
    if finding.get("SchemaVersion") != "2018-10-08":
        raise ValueError("unsupported ASFF schema version")
    for field in ("Title", "Description", "AwsAccountId", "GeneratorId"):
        if not isinstance(finding.get(field), str) or not finding[field].strip():
            raise ValueError(f"{field} must be a nonempty string")
    if not isinstance(finding.get("Types"), list) or not finding["Types"]:
        raise ValueError("Types must be a nonempty list")
    created, updated = timestamp(finding.get("CreatedAt")), timestamp(finding.get("UpdatedAt"))
    if updated < created:
        raise ValueError("UpdatedAt precedes CreatedAt")
    severity = finding.get("Severity", {})
    if not isinstance(severity, dict) or severity.get("Label") not in SLA_DAYS:
        raise ValueError("Severity.Label must be a supported severity")
    resources = finding.get("Resources")
    if not isinstance(resources, list) or not resources or any(
        not isinstance(r, dict) or not isinstance(r.get("Id"), str) or not r["Id"]
        or not isinstance(r.get("Type"), str) or not r["Type"] for r in resources
    ):
        raise ValueError("Resources must contain objects with Id and Type")
    workflow = finding.get("Workflow", {})
    if not isinstance(workflow, dict) or workflow.get("Status", "NEW") not in {
        "NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"
    }:
        raise ValueError("unsupported Workflow.Status")
    if finding.get("RecordState", "ACTIVE") not in {"ACTIVE", "ARCHIVED"}:
        raise ValueError("unsupported RecordState")
    vulns = finding.get("Vulnerabilities", [])
    if not isinstance(vulns, list) or any(not isinstance(v, dict) for v in vulns):
        raise ValueError("Vulnerabilities must be a list of objects")
    if "LastObservedAt" in finding:
        timestamp(finding["LastObservedAt"])
    return updated


def triage(document, annotations, as_of, stale_days=14):
    """Retain one row per (ProductArn, Id); never merge by CVE or resource."""
    if not isinstance(document, dict) or not isinstance(document.get("Findings"), list):
        raise ValueError("input must be an object containing a Findings list")
    if not isinstance(annotations, list):
        raise ValueError("annotations must be a list")
    if stale_days < 0:
        raise ValueError("stale_days must be nonnegative")
    annotated = {}
    for item in annotations:
        if not isinstance(item, dict):
            raise ValueError("annotation must be an object")
        key = identity(item)
        if key in annotated:
            raise ValueError("duplicate annotation identity")
        annotated[key] = item
    grouped, invalid = defaultdict(list), []
    for index, finding in enumerate(document["Findings"]):
        try:
            updated = validate(finding)
            grouped[identity(finding)].append((updated, canonical(finding), index, finding))
        except (ValueError, TypeError) as exc:
            invalid.append({"input_index": index, "reason": str(exc)})
    rows = []
    for key, snapshots in sorted(grouped.items()):
        # Equal-time conflicting records remain visibly ambiguous; the tie-break only
        # makes report generation reproducible and does not claim a true latest state.
        updated, _, _, finding = max(snapshots, key=lambda s: (s[0], s[1]))
        latest = [s for s in snapshots if s[0] == updated]
        flags = []
        if len({s[1] for s in latest}) > 1:
            flags.append("conflicting_latest_snapshots")
        created = timestamp(finding["CreatedAt"])
        if updated > as_of or created > as_of:
            flags.append("future_timestamp")
        observed = timestamp(finding["LastObservedAt"]) if "LastObservedAt" in finding else None
        if observed is None:
            flags.append("observation_time_missing")
        elif observed > as_of:
            flags.append("future_observation")
        elif as_of - observed > timedelta(days=stale_days):
            flags.append("stale_observation")
        severity = finding["Severity"]["Label"]
        due = created + timedelta(days=SLA_DAYS[severity])
        annotation = annotated.get(key, {})
        owner = annotation.get("owner")
        if not isinstance(owner, str) or not owner.strip():
            owner = None
            flags.append("owner_missing")
        exception = annotation.get("exception")
        exception_state = "none"
        if exception is not None:
            exception_state = "invalid"
            if isinstance(exception, dict) and owner and all(
                isinstance(exception.get(k), str) and exception[k].strip()
                for k in ("reason", "ticket", "expires_at")
            ):
                try:
                    exception_state = "active" if timestamp(exception["expires_at"]) > as_of else "expired"
                except ValueError:
                    pass
            if exception_state != "active":
                flags.append("exception_" + exception_state)
        workflow = finding.get("Workflow", {}).get("Status", "NEW")
        state = finding.get("RecordState", "ACTIVE")
        if workflow == "SUPPRESSED" and exception_state != "active":
            flags.append("suppression_without_active_exception")
        open_record = state == "ACTIVE" and workflow != "RESOLVED"
        needs_action = open_record and (workflow != "SUPPRESSED" or exception_state != "active")
        exploitable = any(v.get("ExploitAvailable") == "YES" for v in finding.get("Vulnerabilities", []))
        priority = "review" if flags else "routine"
        if needs_action and (severity in {"CRITICAL", "HIGH"} or exploitable or due < as_of):
            priority = "urgent_review"
        rows.append({
            "finding_key": hashlib.sha256(canonical(key).encode()).hexdigest()[:16],
            "ProductArn": key[0], "Id": key[1], "title": finding["Title"],
            "severity": severity, "resources": sorted({r["Id"] for r in finding["Resources"]}),
            "vulnerability_ids": sorted({v["Id"] for v in finding.get("Vulnerabilities", []) if isinstance(v.get("Id"), str)}),
            "provider_updated_at": updated.isoformat(),
            "last_observed_at": observed.isoformat() if observed else None,
            "record_state": state, "workflow_status": workflow,
            "owner": owner, "exception_state": exception_state,
            "illustrative_due_at": due.isoformat(), "overdue": needs_action and due < as_of,
            "exploit_available_reported": exploitable, "priority": priority,
            "quality_flags": sorted(flags), "source_indices": sorted(s[2] for s in snapshots)
        })
    rank = {"urgent_review": 0, "review": 1, "routine": 2}
    rows.sort(key=lambda row: (rank[row["priority"]], row["finding_key"]))
    return {
        "as_of": as_of.isoformat(), "scope": "offline snapshot; illustrative triage, no remediation verification",
        "summary": {"input_records": len(document["Findings"]), "unique_findings": len(rows),
                    "duplicate_records": sum(len(v) - 1 for v in grouped.values()),
                    "invalid_records": len(invalid), "priorities": dict(Counter(r["priority"] for r in rows))},
        "unused_annotations": [{"ProductArn": k[0], "Id": k[1]} for k in sorted(set(annotated) - set(grouped))],
        "invalid_records": invalid, "findings": rows
    }


def markdown(report):
    def cell(value):
        text = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
        for char in "|[]()`":
            text = text.replace(char, f"&#{ord(char)};")
        return text
    lines = ["# Security findings triage", "", f"As of: {report['as_of']}", "",
             "Offline evidence only. Source workflow state does not prove remediation.", "",
             "| Finding | Severity | Priority | Owner | Data-quality flags |",
             "|---|---|---|---|---|"]
    for row in report["findings"]:
        lines.append("| " + " | ".join(cell(x) for x in [row["title"], row["severity"], row["priority"], row["owner"] or "UNASSIGNED", ", ".join(row["quality_flags"]) or "none"]) + " |")
    lines.extend(["", "Summary: " + json.dumps(report["summary"], sort_keys=True),
                  "", "Full source identities and snapshot indices are preserved in the JSON report.", ""])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--annotations", type=Path)
    parser.add_argument("--as-of", required=True, help="Explicit timezone-aware timestamp for reproducible results")
    parser.add_argument("--stale-days", type=int, default=14)
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args(argv)
    try:
        report = triage(json.loads(args.input.read_text()), json.loads(args.annotations.read_text()) if args.annotations else [], timestamp(args.as_of), args.stale_days)
    except (OSError, ValueError, TypeError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    print(markdown(report) if args.format == "markdown" else json.dumps(report, indent=2, sort_keys=True))
    return 2 if report["invalid_records"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
