from io import BytesIO
from pathlib import Path

from app import app
from scanner.analyzer import analyze_code
from reports.report_generator import generate_report_pdf


def test_vulnerable_sample_covers_all_six_categories():
    code = Path("test_samples/vulnerable_app.py").read_text(encoding="utf-8")
    result = analyze_code(code)
    categories = {finding["category"] for finding in result["findings"]}
    assert len(categories) == 6
    assert result["syntax_error"] is None


def test_safer_sample_has_no_weakness_findings():
    code = Path("test_samples/safer_app.py").read_text(encoding="utf-8")
    categories = {finding["category"] for finding in analyze_code(code)["findings"]}
    assert categories <= {"Dependency Management"}


def test_invalid_and_empty_source_are_rejected():
    client = app.test_client()
    assert client.post("/api/scan", json={"code": ""}).status_code == 400
    assert client.post("/api/scan", json={"code": "def broken("}).get_json()["syntax_error"]


def test_upload_validates_extension_and_reads_text_only():
    client = app.test_client()
    invalid = client.post("/api/upload", data={"file": (BytesIO(b"print('x')"), "sample.txt")})
    assert invalid.status_code == 400
    valid = client.post("/api/upload", data={"file": (BytesIO(b"print('x')"), "sample.py")})
    assert valid.status_code == 200
    assert valid.get_json()["code"] == "print('x')"


def test_upload_rejects_oversized_source():
    client = app.test_client()
    response = client.post("/api/upload", data={"file": (BytesIO(b"x" * 500001), "large.py")})
    assert response.status_code == 413


def test_security_headers_and_example_route():
    client = app.test_client()
    response = client.get("/api/example/safer")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_scan_and_report_endpoint_return_timestamped_pdf_download():
    client = app.test_client()
    scan_response = client.post("/api/scan", json={
        "code": 'import os\nuser = input()\nos.system(user)\n'
    })
    assert scan_response.status_code == 200
    result = scan_response.get_json()
    assert result["scanned_at"]
    result["analyzed_filename"] = "sample & review.py"

    response = client.post("/api/report", json={"result": result})

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert "attachment;" in response.headers["Content-Disposition"]
    assert "SecureCodeAudit_Report_" in response.headers["Content-Disposition"]
    assert response.headers["Content-Disposition"].endswith(".pdf")
    assert response.data.startswith(b"%PDF-")
    assert response.data.rstrip().endswith(b"%%EOF")


def test_report_accepts_zero_findings_and_missing_optional_metadata():
    pdf = generate_report_pdf({"findings": []})
    content = pdf.getvalue()
    assert content.startswith(b"%PDF-")
    assert content.rstrip().endswith(b"%%EOF")


def test_report_handles_long_unicode_metadata_and_paginated_findings():
    finding = {
        "severity": "High",
        "priority": 1,
        "line": 42,
        "title": "Potentially unsafe dynamic path",
        "description": "Descripción & validation <required>. " * 80,
        "impact": "A long impact description. " * 80,
        "recommendation": "Resolve and validate the candidate path. " * 80,
        "secure_example": 'candidate = base / "trusted.py"\nif not candidate.is_relative_to(base): raise ValueError("invalid")',
        "principles": ["Input Validation", "Least Privilege"],
    }
    findings = [dict(finding) for _ in range(75)]
    pdf = generate_report_pdf({
        "findings": findings,
        "analyzed_filename": "á" + "long_name_" * 35 + "&report.py",
    })
    content = pdf.getvalue()
    assert content.startswith(b"%PDF-")
    assert content.rstrip().endswith(b"%%EOF")
    assert b"TimesNewRomanPSMT" in content or b"/Times-Roman" in content


def test_report_endpoint_rejects_missing_or_invalid_scan_results():
    client = app.test_client()
    assert client.post("/api/report", json={}).status_code == 400
    response = client.post("/api/report", json={"result": {"findings": ["not a finding"]}})
    assert response.status_code == 400