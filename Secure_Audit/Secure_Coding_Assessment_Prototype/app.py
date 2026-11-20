from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
from werkzeug.exceptions import RequestEntityTooLarge
from io import TextIOWrapper
from datetime import datetime, timezone
from uuid import uuid4
from scanner.analyzer import analyze_code
from scanner.mappings import add_finding_metadata, finding_identifier
from scanner.project_scan import ProjectArchiveError, scan_project_archive
from scanner.git_scan import GitRepositoryError, scan_github_repository
from scanner.assessment import RISK_METHOD, checklist_results, risk_level
from scanner.dependency_audit import MAX_MANIFEST_BYTES, audit_manifest
from reports.report_generator import generate_report_pdf
from reports.exporters import generate_csv, generate_json, prepare_report_data

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response

@app.errorhandler(RequestEntityTooLarge)
def request_too_large(error):
    return jsonify({"error": "The request exceeds the 20 MB application limit. Individual source files and dependency manifests have lower limits."}), 413

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.get("/findings")
def findings():
    return render_template("findings.html")

@app.get("/risk")
def risk():
    return render_template("risk.html")

@app.get("/principles")
def principles():
    return render_template("principles.html")

@app.get("/reports")
def reports():
    return render_template("reports.html")

@app.get("/dependencies")
def dependencies_page():
    return render_template("dependencies.html")

@app.get("/checklist")
def checklist_page():
    return render_template("checklist.html")

@app.get("/history")
def history_page():
    return render_template("history.html")

@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "The scan request must be a JSON object."}), 400
    code = payload.get("code", "")
    if not isinstance(code, str) or not code.strip():
        return jsonify({"error": "Please provide Python source code."}), 400
    if len(code) > 500_000:
        return jsonify({"error": "Code sample is too large."}), 413
    result = analyze_code(code)
    filename = Path(str(payload.get("filename") or "source.py")).name
    enriched_findings = []
    for finding in result["findings"]:
        enriched = add_finding_metadata(finding, filename)
        enriched["finding_id"] = finding_identifier(enriched)
        enriched_findings.append(enriched)
    result["findings"] = enriched_findings
    result["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["scan_type"] = "single"
    result["analyzed_filename"] = filename
    result["scan_id"] = str(uuid4())
    result["risk_level"] = risk_level(result["findings"])
    result["risk_method"] = RISK_METHOD
    result["checklist"] = checklist_results(result["findings"], bool(result["syntax_error"]))
    return jsonify(result)

@app.post("/api/upload")
def upload():
    if request.content_length and request.content_length > 1 * 1024 * 1024:
        return jsonify({"error": "The submitted source is too large. Maximum size is 1 MB."}), 413
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Choose a Python file to upload."}), 400
    if not uploaded.filename.lower().endswith(".py"):
        return jsonify({"error": "Only .py files are accepted."}), 400
    try:
        text = TextIOWrapper(uploaded.stream, encoding="utf-8", errors="strict").read(500_001)
    except UnicodeDecodeError:
        return jsonify({"error": "The file must be valid UTF-8 text."}), 400
    if len(text) > 500_000:
        return jsonify({"error": "Code sample is too large."}), 413
    return jsonify({"code": text})

@app.post("/api/scan/project")
def scan_project():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Choose a ZIP archive containing a Python project."}), 400
    if not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"error": "Only .zip project archives are accepted."}), 400
    archive_data = uploaded.stream.read(20 * 1024 * 1024 + 1)
    if len(archive_data) > 20 * 1024 * 1024:
        return jsonify({"error": "The project archive exceeds the 20 MB limit."}), 413
    try:
        result = scan_project_archive(archive_data, uploaded.filename)
    except ProjectArchiveError as error:
        return jsonify({"error": str(error)}), 400
    result["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["scan_id"] = str(uuid4())
    result["risk_level"] = risk_level(result["findings"])
    result["risk_method"] = RISK_METHOD
    result["checklist"] = checklist_results(result["findings"], result["syntax_errors"] > 0)
    return jsonify(result)

@app.post("/api/scan/github")
def scan_github():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
        return jsonify({"error": "Provide a public GitHub repository URL."}), 400
    try:
        result = scan_github_repository(payload["url"])
    except GitRepositoryError as error:
        return jsonify({"error": str(error)}), error.status_code
    result["scanned_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result["scan_id"] = str(uuid4())
    result["risk_level"] = risk_level(result["findings"])
    result["risk_method"] = RISK_METHOD
    result["checklist"] = checklist_results(result["findings"], result["syntax_errors"] > 0)
    return jsonify(result)

@app.post("/api/dependencies/audit")
def audit_dependencies():
    uploaded = request.files.get("manifest")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Choose a supported dependency manifest."}), 400
    filename = Path(uploaded.filename.replace("\\", "/")).name
    if not (filename.lower() == "requirements.txt" or filename.lower() == "pyproject.toml"):
        return jsonify({"error": "Only requirements.txt and pyproject.toml are supported."}), 400
    manifest_bytes = uploaded.stream.read(MAX_MANIFEST_BYTES + 1)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        return jsonify({"error": "The dependency manifest exceeds the 1 MB limit."}), 413
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "The dependency manifest must be valid UTF-8 text."}), 400
    try:
        result = audit_manifest(text, filename)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(result)

@app.get("/api/example/<kind>")
def example(kind):
    if kind not in {"vulnerable", "safer"}:
        return jsonify({"error": "Unknown example."}), 404
    sample_path = Path(app.root_path) / "test_samples" / f"{kind}_app.py"
    return jsonify({"code": sample_path.read_text(encoding="utf-8")})

@app.post("/api/report")
def report():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"error": "The report request must be a JSON object."}), 400
    result = payload.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("findings"), list):
        return jsonify({"error": "A completed scan result is required."}), 400
    if any(not isinstance(finding, dict) for finding in result["findings"]):
        return jsonify({"error": "Scan results contain an invalid finding."}), 400
    report_format = payload.get("format", "pdf")
    if not isinstance(report_format, str) or report_format not in {"pdf", "csv", "json"}:
        return jsonify({"error": "Unsupported report format."}), 400
    options = payload.get("options", {})
    if not isinstance(options, dict):
        return jsonify({"error": "Report options must be an object."}), 400
    if not isinstance(result.get("not_detected_findings", []), list):
        return jsonify({"error": "Scan results contain invalid finding tracking data."}), 400
    dependencies = result.get("dependency_results")
    if dependencies is not None and (
        not isinstance(dependencies, dict)
        or not isinstance(dependencies.get("results", []), list)
        or any(not isinstance(item, dict) for item in dependencies.get("results", []))
    ):
        return jsonify({"error": "Scan results contain invalid dependency audit data."}), 400
    try:
        data = prepare_report_data(result, options)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    if report_format == "csv":
        return send_file(
            generate_csv(data),
            mimetype="text/csv; charset=utf-8",
            as_attachment=True,
            download_name=f"SecureCodeAudit_Report_{datetime.now().date().isoformat()}.csv",
        )
    if report_format == "json":
        return send_file(
            generate_json(data),
            mimetype="application/json; charset=utf-8",
            as_attachment=True,
            download_name=f"SecureCodeAudit_Report_{datetime.now().date().isoformat()}.json",
        )
    try:
        pdf = generate_report_pdf(data)
    except (KeyError, TypeError, ValueError) as error:
        return jsonify({"error": f"Unable to generate the report: {error}"}), 400
    filename = f"SecureCodeAudit_Report_{datetime.now().date().isoformat()}.pdf"
    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )

if __name__ == "__main__":
    app.run(debug=False)
