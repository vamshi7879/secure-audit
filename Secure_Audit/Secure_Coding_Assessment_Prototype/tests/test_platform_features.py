from __future__ import annotations

import csv
import ast
from collections import deque
from io import BytesIO, StringIO
import json
import re
import stat
import zipfile

import pytest
from pypdf import PdfReader

from app import app
from reports.exporters import generate_csv, generate_json, prepare_report_data
from reports.report_generator import _times_font_paths, generate_report_pdf
from scanner import dependency_audit
from scanner.assessment import checklist_results, risk_level
from scanner.configuration import check_secure_configuration
from scanner.git_scan import GitRepositoryError, _parse_github_url, scan_github_repository
from scanner.mappings import add_finding_metadata, finding_identifier
from scanner.project_scan import ProjectArchiveError, scan_project_archive


def make_zip(files: dict[str, bytes], symlink: str | None = None) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target.py")
    return stream.getvalue()


def test_project_zip_scan_reports_relative_file_line_and_skipped_files():
    archive = make_zip({
        "src/app.py": b"import os\nuser = input()\nos.system(user)\n",
        "README.md": b"not executed",
    })

    result = scan_project_archive(archive, "demo.zip")

    assert result["files_analyzed"] == ["src/app.py"]
    assert result["files_skipped"] == ["README.md"]
    finding = next(item for item in result["findings"] if item["rule_id"] == "CMD-001")
    assert finding["file"] == "src/app.py"
    assert finding["line"] == 3
    assert finding["finding_id"] == finding_identifier(finding)


@pytest.mark.parametrize(
    ("archive", "message"),
    [
        (b"not a zip file", "valid ZIP"),
        (make_zip({"../escape.py": b"print(1)"}), "unsafe file path"),
        (make_zip({}, symlink="link.py"), "Symbolic links"),
        (make_zip({"README.md": b"no python"}), "no supported Python"),
        (make_zip({"." : b"invalid path"}), "unsafe file path"),
    ],
)
def test_project_zip_rejects_invalid_or_unsafe_archives(archive, message):
    with pytest.raises(ProjectArchiveError, match=message):
        scan_project_archive(archive)


def test_project_zip_rejects_oversized_source_before_analysis():
    archive = make_zip({"large.py": b"#" * (2 * 1024 * 1024 + 1)})

    with pytest.raises(ProjectArchiveError, match="per-file limit"):
        scan_project_archive(archive)


def test_configuration_checks_redact_secret_literals():
    code = 'DEBUG = True\nSECRET_KEY = "this-secret-must-not-leak"\n'
    findings = check_secure_configuration(ast.parse(code), code)

    assert {item["id"] for item in findings} == {"CONFIG-DEBUG-001", "CONFIG-SECRET-001"}
    assert all("this-secret-must-not-leak" not in str(item) for item in findings)


def test_checklist_never_marks_nonmatching_rules_as_pass_and_risk_is_categorical():
    checklist = checklist_results([])

    assert checklist
    assert all(item["status"] == "Not Assessed" for item in checklist)
    assert risk_level([]) == "Low"
    assert risk_level([{"severity": "High"}]) == "High"
    assert "No numeric score" in __import__("scanner.assessment", fromlist=["RISK_METHOD"]).RISK_METHOD


def test_pyproject_audit_parses_project_and_poetry_dependency_tables(monkeypatch):
    monkeypatch.setattr(
        dependency_audit,
        "_osv_query",
        lambda packages: (
            {"results": [{"vulns": []}, {"vulns": []}]},
            None,
        ),
    )
    manifest = """
[project]
dependencies = ["Requests==2.32.0"]

[tool.poetry.group.dev.dependencies]
urllib3 = "==2.2.1"
"""

    result = dependency_audit.audit_manifest(manifest, "pyproject.toml")

    assert result["status"] == "OSV lookup completed"
    assert [(item["package"], item["version"]) for item in result["results"]] == [
        ("Requests", "2.32.0"),
        ("urllib3", "2.2.1"),
    ]
    assert all(item["status"] == "No known vulnerabilities found" for item in result["results"])


def test_dependency_lookup_failure_is_not_reported_as_safe(monkeypatch):
    monkeypatch.setattr(dependency_audit, "_osv_query", lambda packages: (None, "unavailable"))

    result = dependency_audit.audit_manifest("urllib3==2.2.0", "requirements.txt")

    assert result["results"][0]["status"] == "Unable to check"
    assert "no safety conclusion" in result["results"][0]["recommendation"]


def test_osv_query_uses_fixed_endpoint_and_rejects_malformed_batch(monkeypatch):
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            captured["read_limit"] = limit
            return b'{"results":[]}'

    class Opener:
        def open(self, request, timeout):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data)
            captured["timeout"] = timeout
            return Response()

    def fake_build_opener(handler):
        return Opener()

    monkeypatch.setattr(dependency_audit, "build_opener", fake_build_opener)
    dependency_audit._CACHE.clear()
    dependency_audit._QUERY_TIMES.clear()
    data, error = dependency_audit._osv_query([{"package": "My_Package", "version": "1.0.0"}])

    assert data is None
    assert error == "OSV response was not in the expected format."
    assert captured["url"] == dependency_audit.OSV_QUERY_URL
    assert captured["payload"]["queries"][0]["package"]["name"] == "my-package"
    assert captured["timeout"] == 5
    dependency_audit._CACHE.clear()
    dependency_audit._QUERY_TIMES.clear()

def test_github_url_validation_rejects_arbitrary_hosts_and_credentials():
    assert _parse_github_url("https://github.com/acme/demo/tree/feature/fix") == (
        "acme",
        "demo",
        "feature/fix",
    )
    for url in (
        "http://github.com/acme/demo",
        "https://github.com.evil.example/acme/demo",
        "https://user:token@github.com/acme/demo",
        "https://github.com/acme/demo?download=1",
        "https://127.0.0.1/acme/demo",
    ):
        with pytest.raises(GitRepositoryError):
            _parse_github_url(url)


def test_github_scan_resolves_and_scans_a_pinned_public_commit(monkeypatch):
    archive = make_zip({"src/app.py": b"import os\nuser = input()\nos.system(user)\n"})
    commit_sha = "a" * 40
    requested = []
    monkeypatch.setattr("scanner.git_scan._REQUEST_TIMES", deque())
    monkeypatch.setattr(
        "scanner.git_scan._github_json",
        lambda url: requested.append(url) or {"sha": commit_sha},
    )
    monkeypatch.setattr(
        "scanner.git_scan._request_bytes",
        lambda url, accept, limit: requested.append(url) or archive,
    )

    result = scan_github_repository("https://github.com/acme/demo/tree/feature/fix")

    assert result["scan_type"] == "git"
    assert result["repository_url"] == "https://github.com/acme/demo/tree/feature/fix"
    assert result["branch"] == "feature/fix"
    assert result["commit_sha"] == commit_sha
    assert result["files_analyzed"] == ["src/app.py"]
    assert requested == [
        "https://api.github.com/repos/acme/demo/commits/feature/fix",
        f"https://codeload.github.com/acme/demo/zip/{commit_sha}",
    ]


def test_github_scan_route_rejects_invalid_hosts_without_fetching():
    client = app.test_client()
    response = client.post("/api/scan/github", json={"url": "https://127.0.0.1/private"})

    assert response.status_code == 400
    assert "github.com" in response.get_json()["error"]


def test_report_exports_filter_findings_and_prevent_csv_formula_injection():
    result = {
        "analyzed_filename": "audit.py",
        "scan_id": "scan-123",
        "findings": [
            {
                "finding_id": "finding-1",
                "rule_id": "CMD-001",
                "severity": "High",
                "title": "=HYPERLINK(\"https://bad.example\")",
                "file": "src/audit.py",
                "line": 4,
                "review": {"status": "In Progress", "notes": "+unsafe note"},
            },
            {"finding_id": "finding-2", "severity": "Low", "title": "Other issue"},
        ],
        "not_detected_findings": [
            {"finding_id": "old-1", "severity": "High", "title": "Old issue", "file": "old.py", "line": 9}
        ],
    }
    report_data = prepare_report_data(result, {"severity": "High"})
    csv_output = generate_csv(report_data).getvalue().decode("utf-8-sig")
    rows = list(csv.DictReader(StringIO(csv_output)))
    json_output = json.loads(generate_json(report_data).getvalue())

    assert report_data["total"] == 1
    assert rows[0]["Title"].startswith("'=")
    assert rows[0]["Review notes"].startswith("'+")
    assert rows[0]["Tracking status"] == "Current scan"
    assert rows[1]["Tracking status"] == "Not detected in the latest scan (not marked resolved)"
    assert json_output["report_metadata"]["scan_id"] == "scan-123"
    assert json_output["report_metadata"]["not_detected_findings"][0]["finding_id"] == "old-1"


def test_export_routes_return_real_attachment_formats_and_validate_options():
    client = app.test_client()
    result = {
        "scan_id": "scan-123",
        "scanned_at": "2025-01-01T00:00:00+00:00",
        "analyzed_filename": "source.py",
        "findings": [],
    }

    for report_format, mime_type, signature in (
        ("pdf", "application/pdf", b"%PDF-"),
        ("csv", "text/csv", b"\xef\xbb\xbf"),
        ("json", "application/json", b"{"),
    ):
        response = client.post(
            "/api/report",
            json={"result": result, "format": report_format, "options": {}},
        )
        assert response.status_code == 200
        assert response.mimetype == mime_type
        assert "attachment;" in response.headers["Content-Disposition"]
        assert response.data.startswith(signature)

    invalid = client.post(
        "/api/report",
        json={"result": result, "format": "pdf", "options": {"severity": "Urgent"}},
    )
    assert invalid.status_code == 400


def test_generated_pdf_text_fonts_pagination_tracking_and_dependency_table():
    long_filename = "secure_audit_é_&_" + "verylongsegment" * 18 + ".zip"
    findings = [
        {
            "finding_id": f"rule-{index:03d}",
            "rule_id": "CMD-001",
            "severity": "High",
            "priority": 1,
            "title": f"Finding {index} & review",
            "description": "Potential dynamic command issue with long Unicode text — " * 12,
            "impact": "Context-dependent impact. " * 8,
            "recommendation": "Validate and constrain command arguments. " * 8,
            "file": f"src/very_long_module_{index}.py",
            "line": index + 1,
            "secure_example": 'subprocess.run(["tool", argument], check=True)',
            "source_snippet": "os.system(user_input)",
            "review": {
                "status": "In Progress",
                "notes": "Reviewed by the local project owner.",
                "created_at": "2025-01-01T00:00:00Z",
                "modified_at": "2025-01-02T00:00:00Z",
            },
        }
        for index in range(30)
    ]
    pdf = generate_report_pdf({
        "scan_id": "scan-report-123",
        "scanned_at": "2025-01-01T00:00:00+00:00",
        "analyzed_filename": long_filename,
        "files_analyzed": ["src/app.py", "src/views.py"],
        "severity_filter": "All severities",
        "findings": findings,
        "not_detected_findings": [
            {**findings[0], "tracking_status": "Not detected in the latest scan"}
        ],
        "dependency_results": {
            "status": "Vulnerabilities reported",
            "results": [{
                "package": "demo-package",
                "version": "1.2.3",
                "vulnerability_id": "GHSA-test-1234",
                "status": "Vulnerability reported",
                "severity": "Not provided by OSV",
                "details": "An advisory summary.",
                "fixed_version": "1.2.4",
                "recommendation": "Review the advisory and update.",
            }],
        },
    })
    reader = PdfReader(pdf)
    pages = [page.extract_text() or "" for page in reader.pages]
    text = "\n".join(pages)

    assert len(pages) > 3
    assert all(page.strip() for page in pages)
    assert "scan-report-123" in text
    assert "rule-000" in text
    assert "GHSA-test-1234" in re.sub(r"\s+", "", text)
    assert "not been marked resolved" in text
    assert "os.system(user_input)" in text
    assert re.sub(r"\s+", "", long_filename) in re.sub(r"\s+", "", text)
    assert "Page 1" not in pages[0]
    assert all(re.search(rf"Page {number}\b", page) for number, page in enumerate(pages[1:], start=1))
    times_embedded = _times_font_paths() is not None
    assert ("Times New Roman (embedded)" in text) == times_embedded
    used_fonts = set()
    for page in reader.pages:
        page.extract_text(visitor_text=lambda extracted, _cm, _tm, font, _size: (
            used_fonts.add(str(font.get("/BaseFont", "unknown")))
            if extracted.strip() and font else None
        ))
    if times_embedded:
        assert all("TimesNewRoman" in font or "Courier" in font for font in used_fonts)
    else:
        assert all(font.startswith("/Times-") or "Courier" in font for font in used_fonts)
    if _times_font_paths():
        embedded_times = any(
            "/FontFile2" in font.get_object().get("/FontDescriptor", {})
            or "/FontFile3" in font.get_object().get("/FontDescriptor", {})
            for page in reader.pages
            for font in page["/Resources"]["/Font"].get_object().values()
            if font.get_object().get("/BaseFont", "").find("TimesNewRoman") >= 0
        )
        assert embedded_times


def test_generated_empty_pdf_handles_missing_metadata_and_has_selectable_text():
    pdf = generate_report_pdf({"findings": []})
    reader = PdfReader(pdf)
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert len(reader.pages) >= 2
    assert all((page.extract_text() or "").strip() for page in reader.pages)
    assert "No configured vulnerability patterns were reported" in text
    assert "Not available" in text
    assert "Page 1" in "\n".join(page.extract_text() or "" for page in reader.pages[1:])
