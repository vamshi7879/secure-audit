# SecureCodeAudit

SecureCodeAudit is an educational Flask application for static analysis of Python source. Submitted source is parsed with Python's AST and is never imported, executed, installed, or sent to a shell. The configured checks identify potential issues and do not prove exploitability or establish that an application is secure.

## Features

- Dashboard, single-file scanner, project findings, risk view, and security-principles view.
- Safe ZIP project scanning with per-file findings, relative file paths, line numbers, severity, CWE/OWASP references, search, filters, sorting, and pagination.
- Public GitHub repository scanning that resolves a branch to a commit SHA and downloads a bounded archive from fixed GitHub hosts. It does not run Git or execute repository content.
- An evidence-aware checklist: detected patterns are marked **Fail**; absence of a match remains **Not Assessed**, not Pass.
- Optional audit of `requirements.txt` and `pyproject.toml` against OSV.dev for exact pinned versions.
- Browser-local scan history and remediation status/notes. A finding absent from a later scan is labeled **Not detected in the latest scan**, not Resolved.
- PDF, CSV, and JSON downloads based on actual scan results. CSV values are escaped against spreadsheet formula injection.
- Garamond-style website typography; Times New Roman PDF text when the complete local font family is available, with a clearly identified Times-Roman fallback otherwise.

## Install and run

Python 3.10 or newer is supported. Runtime dependencies, including ReportLab, are listed in `requirements.txt`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. To run the test suite, install the development dependencies and run pytest:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

On Linux/macOS, activate `.venv` with `source .venv/bin/activate` before running the same pip and pytest commands.

## Scanning

Open **Code Scanner** and select one of:

1. **Single Python File** — paste source or upload a UTF-8 `.py` file.
2. **Full Python Project** — upload or drop a ZIP archive.
3. **Public GitHub Repository** — enter a public `https://github.com/owner/repository` or `https://github.com/owner/repository/tree/branch` URL. The repository and branch must be public; credentials and arbitrary hosts are rejected. GitHub redirects are not followed. The resolved commit is shown with the results.

ZIP project scans do not extract files to disk. They reject traversal-like paths, symbolic links, duplicate entries, encrypted archives, invalid UTF-8, and over-limit archives. Limits are 20 MB per archive, 1,000 ZIP entries, 300 Python files, 2 MB per Python file, and 25 MB combined Python source. Single-source input is limited to 500,000 characters. Only `.py` files are analyzed; other archive entries are listed as skipped.

GitHub scans are limited to public GitHub repositories and a maximum 20 scans per running application process per hour. Repository metadata is obtained from `api.github.com`; commit archives are fetched from `codeload.github.com`, with 5-second request timeouts, no redirects, and a 20 MB response limit. No Git executable, access token, or repository code execution is used.

## Dependency audit

Open **Dependencies**, upload `requirements.txt` or `pyproject.toml`, and explicitly select **Check against OSV**. Only package names and exact pinned versions are sent to the fixed OSV.dev query endpoint. Unpinned requirements, lookup failures, and empty advisory responses are not treated as proof of safety. Packages are not installed. The manifest is limited to 1 MB and 100 dependencies.

An OSV advisory check is separate from the source scanner. It is attached to the current browser-selected scan when available and included in its PDF/JSON report. Advisory results without a vulnerability rating preserve OSV's raw data; no severity is invented.

## Reports

After a scan, select **Generate Security Report** on the results or open **Reports** and select **Download PDF**, **Download CSV**, or **Download JSON**. Reports use the selected scan from this browser and reflect current local review notes. The severity filter limits included findings; the displayed overall risk remains calculated from all findings in the scan.

PDF reports use ReportLab Platypus. If all four Times New Roman variants are available locally and their font metadata permits subsetting/embedding, they are registered and embedded. The application checks the Windows font directory and known macOS/Linux locations instead of assuming a path. If the family is unavailable or cannot be safely embedded, the PDF explicitly identifies ReportLab's built-in Times-Roman fallback and does not label it Times New Roman. Source snippets use Courier monospace.

## Storage and limitations

Scan history and remediation review records are stored in this browser's `localStorage` (up to 25 scans); they are not synchronized, backed up, or stored in a server database. Generated exports are downloaded directly and are not retained by the app.

The scanner uses configured pattern-based checks and does not provide complete data-flow analysis, runtime testing, or a security certification. CWE and OWASP references are rule-level associations that may require review. A clean scan, an OSV response with no advisory, or an absent finding does not establish that an application is safe. GitHub access is intentionally limited to public repositories on GitHub.com; GitLab, private repositories, and arbitrary Git URLs are not supported.

## Test samples

`test_samples/vulnerable_app.py` and `test_samples/safer_app.py` are analyzed as text in the test suite. Do not execute the intentionally vulnerable sample.
