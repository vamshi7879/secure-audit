from __future__ import annotations

import csv
from datetime import datetime, timezone
from io import BytesIO, StringIO
import json
from pathlib import PurePosixPath

from scanner.assessment import RISK_METHOD, checklist_results, risk_level

FINDING_EXPORT_FIELDS = (
    "finding_id",
    "rule_id",
    "id",
    "severity",
    "priority",
    "category",
    "title",
    "description",
    "file",
    "line",
    "cwe",
    "owasp",
    "mapping_status",
    "principles",
    "impact",
    "recommendation",
    "secure_example",
    "status",
    "review",
    "tracking_status",
)
CSV_COLUMNS = (
    "Finding ID",
    "Severity",
    "Priority",
    "Rule ID",
    "Title",
    "Description",
    "File path",
    "Line number",
    "CWE ID",
    "OWASP reference",
    "Security principles affected",
    "Recommendation",
    "Finding status",
    "Review notes",
    "Review created",
    "Review updated",
    "Tracking status",
)


def prepare_report_data(result: dict, options: dict | None = None) -> dict:
    options = options or {}
    severity = options.get("severity")
    if severity not in (None, "", "Critical", "High", "Medium", "Low", "Info"):
        raise ValueError("Unsupported report severity filter.")
    for option in ("include_remediation", "include_mappings", "include_principles", "include_metadata"):
        if option in options and not isinstance(options[option], bool):
            raise ValueError(f"Report option '{option}' must be a boolean.")
    findings = [
        {key: finding[key] for key in FINDING_EXPORT_FIELDS if key in finding}
        for finding in result["findings"]
        if not severity or finding.get("severity") == severity
    ]
    for finding in findings:
        file_path = str(finding.get("file") or result.get("analyzed_filename") or "Not available").replace("\\", "/")
        path = PurePosixPath(file_path)
        finding["file"] = path.name if path.is_absolute() or ".." in path.parts else path.as_posix()
        if not options.get("include_remediation", True):
            finding.pop("recommendation", None)
            finding.pop("secure_example", None)
        if not options.get("include_mappings", True):
            finding.pop("cwe", None)
            finding.pop("owasp", None)
            finding.pop("mapping_status", None)
        if not options.get("include_principles", True):
            finding.pop("principles", None)
    not_detected = [
        {key: finding[key] for key in FINDING_EXPORT_FIELDS if key in finding}
        for finding in result.get("not_detected_findings", [])
        if isinstance(finding, dict) and (not severity or finding.get("severity") == severity)
    ]
    for finding in not_detected:
        file_path = str(finding.get("file") or result.get("analyzed_filename") or "Not available").replace("\\", "/")
        path = PurePosixPath(file_path)
        finding["file"] = path.name if path.is_absolute() or ".." in path.parts else path.as_posix()
        finding["tracking_status"] = "Not detected in the latest scan (not marked resolved)"
    counts = {
        level: sum(finding.get("severity") == level for finding in findings)
        for level in ("Critical", "High", "Medium", "Low", "Info")
    }
    risk = risk_level(result["findings"])
    checklist = checklist_results(
        findings,
        bool(result.get("syntax_error") or result.get("syntax_errors")),
    )
    dependencies = result.get("dependency_results", {"status": "Not assessed", "results": []})
    dep_check = next((item for item in checklist if item["rule_id"] == "DEP-001"), None)
    if dep_check and isinstance(dependencies, dict):
        dependency_results = dependencies.get("results", [])
        vulnerable = [item for item in dependency_results if item.get("status") == "Vulnerability reported"]
        unassessed = [
            item for item in dependency_results
            if item.get("status") not in ("Vulnerability reported", "No known vulnerabilities found")
        ]
        if vulnerable:
            dep_check["status"] = "Fail"
            dep_check["evidence"] = "; ".join(
                f"{item.get('package', 'Unknown package')} {item.get('version') or ''}: "
                f"{item.get('vulnerability_id', 'advisory reported')}"
                for item in vulnerable
            )
        elif dependency_results:
            dep_check["status"] = "Not Assessed"
            if unassessed:
                dep_check["evidence"] = "; ".join(
                    f"{item.get('package', 'Unknown package')}: {item.get('details') or item.get('status')}"
                    for item in unassessed
                )
            else:
                dep_check["evidence"] = (
                    f"OSV returned no known advisory for {len(dependency_results)} exact pinned version(s). "
                    "This is not a pass or a guarantee of safety."
                )
    return {
        "scan_id": result.get("scan_id"),
        "scan_type": result.get("scan_type", "single"),
        "scanned_at": result.get("scanned_at"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "analyzed_filename": result.get("analyzed_filename"),
        "files_analyzed": result.get("files_analyzed") or [result.get("analyzed_filename", "Not available")],
        "files_supported": result.get("files_supported"),
        "files_skipped": result.get("files_skipped", []),
        "total": len(findings),
        "counts": counts,
        "risk_level": risk,
        "severity_filter": severity or "All severities",
        "risk_method": RISK_METHOD,
        "checklist": checklist,
        "dependency_results": dependencies,
        "not_detected_findings": not_detected,
        "summary": result.get("summary"),
        "include_metadata": bool(options.get("include_metadata", True)),
        "findings": findings,
    }


def _cwe(finding: dict) -> str:
    value = finding.get("cwe")
    return str(value.get("id", "")) if isinstance(value, dict) else ""


def _owasp(finding: dict) -> str:
    value = finding.get("owasp")
    return " — ".join(str(value.get(key, "")) for key in ("id", "title") if value.get(key)) if isinstance(value, dict) else ""


def _safe_csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text


def generate_csv(data: dict) -> BytesIO:
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    all_findings = [
        {**finding, "tracking_status": finding.get("tracking_status") or "Current scan"}
        for finding in data["findings"]
    ] + data.get("not_detected_findings", [])
    for index, finding in enumerate(all_findings, start=1):
        review = finding.get("review") if isinstance(finding.get("review"), dict) else {}
        writer.writerow([
            _safe_csv_cell(finding.get("finding_id") or ""),
            _safe_csv_cell(finding.get("severity")),
            _safe_csv_cell(finding.get("priority")),
            _safe_csv_cell(finding.get("rule_id") or finding.get("id")),
            _safe_csv_cell(finding.get("title") or finding.get("category")),
            _safe_csv_cell(finding.get("description")),
            _safe_csv_cell(finding.get("file")),
            _safe_csv_cell(finding.get("line")),
            _safe_csv_cell(_cwe(finding)),
            _safe_csv_cell(_owasp(finding)),
            _safe_csv_cell(finding.get("principles")),
            _safe_csv_cell(finding.get("recommendation")),
            _safe_csv_cell(review.get("status") or finding.get("status") or "Open"),
            _safe_csv_cell(review.get("notes")),
            _safe_csv_cell(review.get("created_at")),
            _safe_csv_cell(review.get("modified_at")),
            _safe_csv_cell(finding.get("tracking_status") or "Current scan"),
        ])
    return BytesIO(output.getvalue().encode("utf-8-sig"))


def generate_json(data: dict) -> BytesIO:
    payload = {
        "report_metadata": {
            "application": "SecureCodeAudit",
            "report_type": "Static Application Security Testing (SAST)",
            "scan_id": data.get("scan_id"),
            "scan_type": data.get("scan_type"),
            "scan_timestamp": data.get("scanned_at"),
            "generated_at": data.get("generated_at"),
            "analyzed_files": data.get("files_analyzed"),
            "files_skipped": data.get("files_skipped"),
            "not_detected_findings": data.get("not_detected_findings", []),
        },
        "summary": {
            "finding_totals": data.get("counts"),
            "total_findings": data.get("total"),
            "overall_risk": data.get("risk_level"),
            "risk_calculation_method": data.get("risk_method"),
        },
        "findings": data["findings"],
        "security_checklist": data.get("checklist", []),
        "dependency_results": data.get("dependency_results"),
    }
    if not data.get("include_metadata"):
        payload["report_metadata"].pop("analyzed_files", None)
        payload["report_metadata"].pop("files_skipped", None)
    return BytesIO(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
