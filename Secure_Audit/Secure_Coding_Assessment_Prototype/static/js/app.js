const severityLevels = ["Critical", "High", "Medium", "Low"];
const findingPageSize = 25;
let analyzedFilename = "Not available";
let findingPageIndex = 0;
let activeFindings = [];

function getStoredScan() {
  try {
    return JSON.parse(localStorage.getItem("lastScan") || "null");
  } catch (error) {
    return null;
  }
}

function storeScan(result) {
  window.lastScan = result;
  result.scan_id ||= (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);
  result.scanned_at ||= new Date().toISOString();
  const previousReviews = getFindingReviews();
  const currentIds = new Set((result.findings || []).map(finding => finding.finding_id));
  (result.findings || []).forEach(finding => {
    const review = previousReviews[finding.finding_id];
    if (review) finding.review = review;
  });
  result.not_detected_findings = [];
  try {
    const history = getScanHistory();
    if (history.length && Array.isArray(history[0].findings)) {
      result.not_detected_findings = history[0].findings
        .filter(finding => finding.finding_id && !currentIds.has(finding.finding_id))
        .map(finding => ({ ...finding, tracking_status: "Not detected in the latest scan" }));
    }
    const nextHistory = [result, ...history.filter(scan => scan.scan_id !== result.scan_id)].slice(0, 25);
    localStorage.setItem("scanHistory", JSON.stringify(nextHistory));
    localStorage.setItem("lastScan", JSON.stringify(result));
  } catch (error) {
    setReportStatus("Scan completed, but browser storage is unavailable; scan history may not persist.", true);
  }
  renderScanHistory();
}

function getScanHistory() {
  try {
    const history = JSON.parse(localStorage.getItem("scanHistory") || "[]");
    return Array.isArray(history)
      ? history.map((scan, index) => ({ ...scan, scan_id: scan.scan_id || `legacy-${index}` }))
      : [];
  } catch (error) {
    return [];
  }
}

function initializeHistoryPage() {
  if (document.getElementById("scan-history-content")) renderScanHistory();
}

function renderScanHistory() {
  const history = getScanHistory();
  const selector = document.getElementById("report-scan");
  if (selector) {
    const selected = selector.value;
    selector.innerHTML = '<option value="">Latest scan</option>' + history.map((scan, index) => {
      const date = scan.scanned_at ? new Date(scan.scanned_at).toLocaleString() : "Date unavailable";
      const scanType = scan.scan_type === "git" ? "GitHub repository" : scan.scan_type === "project" ? "Project" : "Single file";
      const label = `${date} — ${scanType} — ${scan.total || 0} finding(s)`;
      return `<option value="${escapeHtml(scan.scan_id || index)}">${escapeHtml(label)}</option>`;
    }).join("");
    selector.value = selected;
  }
  const container = document.getElementById("scan-history-content");
  if (!container) return;
  if (!history.length) {
    container.innerHTML = '<div class="empty-state compact"><strong>No scan history available</strong><p>Completed scans will appear here in this browser.</p><a class="button" href="/scanner">Run a Scan</a></div>';
    return;
  }
  const notDetected = history[0]?.not_detected_findings || [];
  const notDetectedSection = notDetected.length
    ? `<section class="not-detected-section"><h3>Not detected in the latest scan</h3><p>These earlier findings were not reported by the latest scan. They have not been marked resolved.</p><ul>${notDetected.map(finding => `<li><strong>${escapeHtml(finding.title || finding.category)}</strong> — ${escapeHtml(finding.file || "Not available")}:${escapeHtml(finding.line || "Not available")} (${escapeHtml(finding.review?.status || finding.status || "Open")})</li>`).join("")}</ul></section>`
    : "";
  container.innerHTML = `${notDetectedSection}<div class="table-scroll"><table class="data-table"><thead><tr><th>Timestamp</th><th>Type</th><th>Analyzed files</th><th>Findings</th><th>Risk</th><th>Not detected in latest scan</th><th></th></tr></thead><tbody>${history.map((scan, index) => {
    const id = escapeHtml(scan.scan_id || String(index));
    const files = scan.files_analyzed?.length ? scan.files_analyzed.join(", ") : scan.analyzed_filename || "Not available";
    const missingCount = index === 0 ? (scan.not_detected_findings || []).length : 0;
    return `<tr><td>${escapeHtml(scan.scanned_at || "Not available")}</td><td>${escapeHtml(scan.scan_type || "single")}</td><td>${escapeHtml(files)}</td><td>${Number(scan.total) || 0}</td><td>${escapeHtml(scan.risk_level || calculateRisk(scan))}</td><td>${missingCount ? `${missingCount} (not marked resolved)` : "—"}</td><td><button class="button secondary" type="button" data-history-select="${id}">Select scan</button></td></tr>`;
  }).join("")}</tbody></table></div><p class="small-note">Showing up to ${history.length} scans stored locally in this browser.</p>`;
  container.querySelectorAll("[data-history-select]").forEach(button => button.addEventListener("click", () => {
    const scan = history.find(item => item.scan_id === button.dataset.historySelect);
    if (!scan) return;
    localStorage.setItem("lastScan", JSON.stringify(scan));
    window.location.href = "/scanner";
  }));
}

function initializeChecklistPage() {
  const container = document.getElementById("checklist-content");
  if (!container) return;
  const result = getStoredScan();
  if (!result) return;
  const checklist = result.checklist || [];
  container.innerHTML = `<div class="checklist-grid">${checklist.map(item => `<article class="checklist-item">
    <div class="finding-top"><h3>${escapeHtml(item.category)} <small>${escapeHtml(item.rule_id)}</small></h3><span class="check-status ${severityClass(item.status).replaceAll(" ", "-")}">${escapeHtml(item.status)}</span></div>
    <p>${escapeHtml(item.check)}</p><p class="finding-label">Evidence</p><p>${escapeHtml(item.evidence)}</p>
    <p class="finding-label">Recommendation</p><p>${escapeHtml(item.recommendation)}</p>
    <p class="finding-label">Related findings</p><p>${item.related_findings?.length || 0}</p>
    <p class="finding-label">Principle</p><p>${escapeHtml(item.principle)}</p>
  </article>`).join("")}</div>`;
}

function initializeDependencyPage() {
  const input = document.getElementById("dependency-manifest");
  const button = document.getElementById("dependency-check-button");
  if (!input || !button) return;
  input.addEventListener("change", () => { button.disabled = !input.files[0]; });
  button.addEventListener("click", async () => {
    const file = input.files[0];
    if (!file) return;
    document.getElementById("dependency-status").textContent = "Parsing manifest and checking pinned packages with OSV...";
    button.disabled = true;
    const form = new FormData();
    form.append("manifest", file);
    try {
      const response = await fetch("/api/dependencies/audit", { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Dependency audit failed.");
      storeDependencyAudit(data);
      document.getElementById("dependency-status").textContent = `${data.status} — checked ${data.checked_at || "timestamp unavailable"}`;
      document.getElementById("dependency-results").innerHTML = `<div class="table-scroll"><table class="data-table"><thead><tr><th>Package</th><th>Version</th><th>Advisory</th><th>Severity</th><th>Source / status</th><th>Remediation</th></tr></thead><tbody>${(data.results || []).map(item => {
        const advisoryId = item.vulnerability_id;
        const advisory = advisoryId
          ? `<a href="https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)}" target="_blank" rel="noopener noreferrer">${escapeHtml(advisoryId)}</a>`
          : escapeHtml(item.status);
        return `<tr><td>${escapeHtml(item.package)}</td><td>${escapeHtml(item.version || "Not pinned")}</td><td>${advisory}</td><td>${escapeHtml(item.severity || "Not available")}</td><td>${escapeHtml(item.source || item.status)}</td><td>${escapeHtml(item.recommendation || "Not available")}</td></tr>`;
      }).join("")}</tbody></table></div>`;
    } catch (error) {
      document.getElementById("dependency-status").textContent = error.message || "Dependency audit failed.";
      document.getElementById("dependency-status").dataset.state = "error";
    } finally {
      button.disabled = false;
    }
  });
}

function storeDependencyAudit(result) {
  try {
    localStorage.setItem("latestDependencyAudit", JSON.stringify(result));
    const latest = getStoredScan();
    if (!latest) return;
    latest.dependency_results = result;
    latest.checklist = applyDependencyAuditToChecklist(latest.checklist || [], result);
    localStorage.setItem("lastScan", JSON.stringify(latest));
    const history = getScanHistory().map(scan => scan.scan_id === latest.scan_id ? latest : scan);
    localStorage.setItem("scanHistory", JSON.stringify(history));
    window.lastScan = latest;
    renderScanHistory();
  } catch (error) {
    setReportStatus("Dependency audit completed, but browser storage is unavailable; it may not be included in reports.", true);
  }
}

function applyDependencyAuditToChecklist(checklist, audit) {
  const item = checklist.find(entry => entry.rule_id === "DEP-001");
  if (!item) return checklist;
  const results = audit.results || [];
  const vulnerable = results.filter(entry => entry.status === "Vulnerability reported");
  const notAssessed = results.filter(entry => entry.status !== "Vulnerability reported" && entry.status !== "No known vulnerabilities found");
  if (vulnerable.length) {
    item.status = "Fail";
    item.evidence = vulnerable.map(entry => `${entry.package} ${entry.version || ""}: ${entry.vulnerability_id || "advisory reported"}`).join("; ");
  } else if (results.length && !notAssessed.length) {
    item.status = "Not Assessed";
    item.evidence = `OSV returned no known advisory for ${results.length} exact pinned version(s). This is not a pass or a guarantee of safety.`;
  } else {
    item.status = "Not Assessed";
    item.evidence = notAssessed.map(entry => `${entry.package}: ${entry.details || entry.status}`).join("; ") || "No dependency advisory lookup has been completed.";
  }
  return checklist;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[character]));
}

function trustedGitHubUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol === "https:" && url.hostname === "github.com"
      && !url.username && !url.password && !url.port && !url.search && !url.hash) return url.href;
  } catch (error) {
    return null;
  }
  return null;
}

function trustedOwaspUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol === "https:" && url.hostname === "owasp.org"
      && !url.username && !url.password && !url.port && url.pathname.startsWith("/Top10/")
      && !url.search && !url.hash) return url.href;
  } catch (error) {
    return null;
  }
  return null;
}

function severityClass(value) {
  return String(value || "info").toLowerCase();
}

function findingMarkup(finding) {
  const principles = (finding.principles || []).map(principle => `<span class="principle-pill">${escapeHtml(principle)}</span>`).join("");
  const status = finding.review?.status || finding.status || "Open";
  const cwe = finding.cwe ? `<a href="https://cwe.mitre.org/data/definitions/${encodeURIComponent(finding.cwe.id.replace("CWE-", ""))}.html" target="_blank" rel="noopener noreferrer">${escapeHtml(finding.cwe.id)} — ${escapeHtml(finding.cwe.title)}</a>` : "Mapping unavailable";
  const owaspUrl = trustedOwaspUrl(finding.owasp?.url);
  const owasp = owaspUrl ? `<a href="${escapeHtml(owaspUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(finding.owasp.id)} — ${escapeHtml(finding.owasp.title)}</a>` : "Mapping unavailable";
  const mappingNote = finding.mapping_status === "review_required"
    ? '<p class="mapping-note">CWE/OWASP associations are tentative rule-level references and require analyst review.</p>'
    : "";
  return `<article id="finding-${escapeHtml(finding.finding_id || "")}" class="finding" data-severity="${escapeHtml(finding.severity)}" data-search="${escapeHtml(`${finding.category} ${finding.title} ${finding.description} ${finding.principles || []}`)}">
    <div class="finding-top"><span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span><span class="priority">Priority ${escapeHtml(finding.priority)}</span></div>
    <h3>${escapeHtml(finding.title || finding.category)}</h3>
    <p class="finding-meta">${escapeHtml(finding.file || "Not available")} / Line ${escapeHtml(finding.line)} / ${escapeHtml(finding.rule_id || finding.id || "Not available")}</p>
    <p>${escapeHtml(finding.description)}</p>
    <div class="finding-divider"></div>
    <p class="finding-label">Why it matters</p><p>${escapeHtml(finding.impact || "Context-dependent security impact.")}</p>
    <p class="finding-label">Recommendation</p><p>${escapeHtml(finding.recommendation)}</p>
    <p class="finding-label">CWE</p><p>${cwe}</p><p class="finding-label">OWASP reference</p><p>${owasp}</p>${mappingNote}
    <p class="finding-label">Security Principles Affected</p><div class="principle-pills">${principles || '<span class="principle-pill">Manual review required</span>'}</div>
    <label class="finding-review-label">Remediation status<select data-review-status="${escapeHtml(finding.finding_id || "")}">
      ${["Open", "In Progress", "Resolved", "False Positive"].map(option => `<option${option === status ? " selected" : ""}>${option}</option>`).join("")}
    </select></label>
    <label class="finding-review-label">Review / remediation notes<textarea data-review-notes="${escapeHtml(finding.finding_id || "")}" rows="2">${escapeHtml(finding.review?.notes || "")}</textarea></label>
  </article>`;
}

function renderSeverityCards(counts, prefix) {
  severityLevels.forEach(level => {
    const element = document.getElementById(`${prefix}-${level.toLowerCase()}`);
    if (element) element.textContent = String((counts && counts[level]) || 0).padStart(2, "0");
  });
}

function calculateRisk(result) {
  if (result?.risk_level) return result.risk_level;
  if (!result || !result.findings || !result.findings.length) return "Low";
  if ((result.counts || {}).Critical) return "Critical";
  if ((result.counts || {}).High) return "High";
  if ((result.counts || {}).Medium) return "Medium";
  return "Low";
}

function renderScanResults(result) {
  const box = document.getElementById("results");
  if (!box) return;
  const counts = result.counts || {};
  const cards = severityLevels.map(level => `<article class="severity-card ${level.toLowerCase()}-card"><span>${level}</span><strong>${String(counts[level] || 0).padStart(2, "0")}</strong><small>${level === "Critical" ? "Immediate review" : "Review priority"}</small></article>`).join("");
  const findings = (result.findings || []).map(findingMarkup).join("");
  const repositoryUrl = trustedGitHubUrl(result.repository_url);
  const repositoryLink = repositoryUrl
    ? `<a href="${escapeHtml(repositoryUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(repositoryUrl)}</a>`
    : escapeHtml(result.repository_url || "Not available");
  const projectSummary = ["project", "git"].includes(result.scan_type)
    ? `<div class="project-scan-summary"><strong>${result.files_supported} Python files analyzed</strong><span>${result.files_skipped.length} unsupported files skipped</span>${result.scan_type === "git" ? `<p>Repository: ${repositoryLink}<br>Branch: ${escapeHtml(result.branch)} / Commit: <code>${escapeHtml(result.commit_sha)}</code></p>` : ""}<ul>${result.file_results.map(file => `<li>${escapeHtml(file.file)} — ${file.findings} finding(s)${file.syntax_error ? ` / ${escapeHtml(file.syntax_error)}` : ""}</li>`).join("")}</ul>${result.files_skipped.length ? `<p>Skipped files: ${result.files_skipped.map(escapeHtml).join(", ")}</p>` : ""}</div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Severity</th><th>Vulnerability</th><th>File</th><th>Line</th><th>CWE</th><th>Principle</th><th>Status</th><th>Details</th></tr></thead><tbody>${result.findings.map(finding => `<tr><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.file)}</td><td>${escapeHtml(finding.line)}</td><td>${escapeHtml(finding.cwe?.id || "Mapping unavailable")}</td><td>${escapeHtml((finding.principles || []).join(", "))}</td><td>${escapeHtml(finding.review?.status || finding.status || "Open")}</td><td><a href="#finding-${escapeHtml(finding.finding_id)}">View details</a></td></tr>`).join("")}</tbody></table></div>`
    : "";
  box.innerHTML = `<div class="result-header"><h2>Security Scan Results</h2><p class="result-subtitle">Scan completed / ${result.total || 0} finding${result.total === 1 ? "" : "s"} detected</p></div>
    ${projectSummary}
    <p class="result-summary">${escapeHtml(result.summary || "Scan completed successfully.")}</p>
    <div class="severity-grid">${cards}</div>
    <div class="result-findings">${findings || '<div class="empty-state compact"><span class="empty-icon">OK</span><strong>No configured patterns detected</strong><p>Manual review is still recommended.</p></div>'}</div>
    ${result.syntax_error ? `<p class="notice"><span class="notice-icon">!</span>${escapeHtml(result.syntax_error)}</p>` : ""}
    <button id="generate-report" class="button" type="button" onclick="downloadReport()">Generate Security Report</button>
    <p id="report-status" role="status" aria-live="polite"></p>`;
  box.classList.remove("hidden");
  document.querySelectorAll("[data-review-status]").forEach(control => control.addEventListener("change", () => {
    saveFindingReview(control.dataset.reviewStatus, { status: control.value });
  }));
  document.querySelectorAll("[data-review-notes]").forEach(control => control.addEventListener("change", () => {
    saveFindingReview(control.dataset.reviewNotes, { notes: control.value });
  }));
  refreshReportAvailability();
}

async function scanCode() {
  const codeElement = document.getElementById("code");
  const box = document.getElementById("results");
  if (!codeElement || !box) return;
  const code = codeElement.value;
  if (!code.trim()) {
    box.classList.remove("hidden");
    box.innerHTML = '<div class="empty-state compact"><span class="empty-icon">!</span><strong>Source code required</strong><p>Please provide Python source code before scanning.</p></div>';
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = '<div class="loading-state"><div><strong>Analyzing source code...</strong><div class="loading-bar"><span></span></div><span>Checking configured secure-coding rules</span></div></div>';
  const started = performance.now();
  try {
    const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code, filename: analyzedFilename }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to analyze the submitted source.");
    data.duration = Math.round(performance.now() - started);
    data.analyzed_filename = analyzedFilename;
    storeScan(data);
    renderScanResults(data);
    renderAllStoredViews(data);
  } catch (error) {
    box.innerHTML = `<div class="empty-state compact"><span class="empty-icon">!</span><strong>Unable to analyze the submitted source</strong><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function clearEditor() {
  const editor = document.getElementById("code");
  const results = document.getElementById("results");
  if (editor) editor.value = "";
  if (results) results.classList.add("hidden");
  updateLineNumbers();
}

async function uploadCode() {
  const file = document.getElementById("file")?.files[0];
  if (!file) { alert("Choose a .py file first."); return; }
  const formData = new FormData();
  formData.append("file", file);
  try {
    const response = await fetch("/api/upload", { method: "POST", body: formData });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Upload failed.");
    document.getElementById("code").value = data.code;
    analyzedFilename = file.name || "Not available";
    updateLineNumbers();
  } catch (error) {
    alert(error.message);
  }
}

async function scanProject() {
  const file = document.getElementById("project-zip")?.files[0];
  const status = document.getElementById("project-status");
  const button = document.getElementById("project-scan-button");
  if (!file || !status || !button) return;
  status.textContent = "Uploading and safely inspecting ZIP contents...";
  button.disabled = true;
  const form = new FormData();
  form.append("file", file);
  try {
    const response = await fetch("/api/scan/project", { method: "POST", body: form });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Project scan failed.");
    storeScan(data);
    renderScanResults(data);
    renderAllStoredViews(data);
    status.textContent = `Project scan completed: ${data.files_supported} Python file(s) analyzed, ${data.files_skipped.length} unsupported file(s) skipped, ${data.total} finding(s).`;
  } catch (error) {
    status.textContent = error.message || "Project scan failed.";
    status.dataset.state = "error";
  } finally {
    button.disabled = false;
  }
}

async function scanGitHub() {
  const input = document.getElementById("github-repository-url");
  const status = document.getElementById("github-status");
  const button = document.getElementById("github-scan-button");
  if (!input || !status || !button) return;
  const url = input.value.trim();
  if (!url) {
    status.textContent = "Enter a public GitHub repository URL.";
    status.dataset.state = "error";
    return;
  }
  status.textContent = "Resolving the public repository branch and downloading a size-limited commit archive...";
  status.dataset.state = "";
  button.disabled = true;
  try {
    const response = await fetch("/api/scan/github", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "GitHub repository scan failed.");
    storeScan(data);
    renderScanResults(data);
    renderAllStoredViews(data);
    status.textContent = `GitHub scan completed at commit ${data.commit_sha}: ${data.files_supported} Python file(s) analyzed, ${data.files_skipped.length} unsupported file(s) skipped, ${data.total} finding(s).`;
    status.dataset.state = "success";
  } catch (error) {
    status.textContent = error.message || "GitHub repository scan failed.";
    status.dataset.state = "error";
  } finally {
    button.disabled = false;
  }
}

async function loadExample(kind) {
  try {
    const response = await fetch(`/api/example/${kind}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to load example.");
    document.getElementById("code").value = data.code;
    analyzedFilename = `${kind}_app.py`;
    updateLineNumbers();
  } catch (error) {
    alert(error.message);
  }
}

function setReportStatus(message, isError = false) {
  const status = document.getElementById("report-status");
  if (status) {
    status.textContent = message;
    status.dataset.state = isError ? "error" : "success";
  } else if (isError) {
    alert(message);
  }
}

function refreshReportAvailability() {
  const result = window.lastScan || getStoredScan();
  document.querySelectorAll("[data-report-format]").forEach(button => {
    button.disabled = !result || !Array.isArray(result.findings);
  });
}

async function downloadReport(data = null, requestedFormat = null) {
  const scanId = document.getElementById("report-scan")?.value || "";
  const selected = scanId ? getScanHistory().find(scan => scan.scan_id === scanId) : null;
  let result = data || selected || window.lastScan || getStoredScan();
  if (!result || !Array.isArray(result.findings)) {
    setReportStatus("Run a security scan before generating a report.", true);
    return;
  }
  const reviews = getFindingReviews();
  result = {
    ...result,
    findings: result.findings.map(finding => ({
      ...finding,
      ...(reviews[finding.finding_id] ? { review: reviews[finding.finding_id] } : {}),
    })),
  };

  try {
    const options = {
      severity: document.getElementById("report-severity")?.value || null,
      include_remediation: document.getElementById("report-remediation")?.checked ?? true,
      include_mappings: document.getElementById("report-mappings")?.checked ?? true,
      include_principles: document.getElementById("report-principles")?.checked ?? true,
    };
    const format = requestedFormat || (data ? "pdf" : document.activeElement?.dataset.reportFormat) || "pdf";
    const response = await fetch("/api/report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ result, format, options }) });
    if (!response.ok) {
      const responseText = await response.text();
      let message = "PDF generation failed. Please try again.";
      try {
        const errorData = JSON.parse(responseText);
        message = errorData.error || message;
      } catch (parseError) {
        // Keep the useful PDF-generation message for non-JSON server errors.
      }
      throw new Error(message);
    }
    const expectedContentType = { pdf: "application/pdf", csv: "text/csv", json: "application/json" }[format];
    if (!(response.headers.get("Content-Type") || "").includes(expectedContentType)) {
      throw new Error(`The server response was not a ${format.toUpperCase()} report.`);
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    const objectUrl = URL.createObjectURL(blob);
    link.href = objectUrl;
    const disposition = response.headers.get("Content-Disposition") || "";
    const filename = disposition.match(/filename="?([^";]+)"?/i);
    link.download = filename ? filename[1] : `SecureCodeAudit_Report_${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    const reportHistory = document.getElementById("report-history");
    if (reportHistory) reportHistory.textContent = `Latest ${format.toUpperCase()} report generated and downloaded.`;
    setReportStatus(`${format.toUpperCase()} report generated and download started.`);
  } catch (error) {
    setReportStatus(error.message || "PDF generation failed. Please try again.", true);
  }
}

function renderDashboard(result) {
  if (!document.getElementById("dashboard-findings")) return;
  const risk = calculateRisk(result);
  document.getElementById("dashboard-scan-status").textContent = "Completed";
  document.getElementById("dashboard-findings").textContent = result.total || 0;
  document.getElementById("dashboard-critical").textContent = (result.counts || {}).Critical || 0;
  document.getElementById("dashboard-risk").textContent = risk;
  const recent = document.getElementById("dashboard-recent");
  if (recent) recent.innerHTML = `<div class="recent-row"><span class="status-dot"></span><div><strong>Latest Python source analysis</strong><p>${result.total || 0} findings / ${escapeHtml(result.summary || "Completed")}</p></div><a class="text-link" href="/findings">View results -&gt;</a></div>`;
}

function renderFindings(result) {
  const list = document.getElementById("findings-list");
  const empty = document.getElementById("findings-empty");
  if (!list || !empty || !result) return;
  activeFindings = result.findings || [];
  empty.classList.toggle("hidden", activeFindings.length > 0);
  list.innerHTML = "";
  if (!activeFindings.length) {
    document.getElementById("finding-count").textContent = "0 of 0 finding(s)";
    document.getElementById("finding-pagination")?.classList.add("hidden");
    return;
  }
  populateFindingFilters(activeFindings);
  updateFindingFilters();
}

function populateFindingFilters(findings) {
  const options = [
    ["finding-severity", findings.map(item => item.severity).filter(Boolean)],
    ["finding-file", findings.map(item => item.file).filter(Boolean)],
    ["finding-cwe", findings.map(item => item.cwe?.id).filter(Boolean)],
    ["finding-owasp", findings.map(item => item.owasp?.id).filter(Boolean)],
    ["finding-principle", findings.flatMap(item => item.principles || [])],
  ];
  options.forEach(([id, values]) => {
    const select = document.getElementById(id);
    if (!select) return;
    const selection = select.value;
    const firstOption = select.options[0].outerHTML;
    select.innerHTML = firstOption + [...new Set(values)].sort().map(value => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
    select.value = selection;
  });
}

function updateFindingFilters() {
  const filters = {
    query: document.getElementById("finding-search")?.value.trim().toLowerCase() || "",
    severity: document.getElementById("finding-severity")?.value || "",
    file: document.getElementById("finding-file")?.value || "",
    cwe: document.getElementById("finding-cwe")?.value || "",
    owasp: document.getElementById("finding-owasp")?.value || "",
    principle: document.getElementById("finding-principle")?.value || "",
    status: document.getElementById("finding-status")?.value || "",
    sort: document.getElementById("finding-sort")?.value || "severity",
  };
  const matches = activeFindings.filter(finding => {
    const review = getFindingReviews()[finding.finding_id];
    const status = review?.status || finding.status || "Open";
    const text = [finding.title, finding.rule_id, finding.id, finding.description, finding.file].join(" ").toLowerCase();
    return (!filters.query || text.includes(filters.query))
      && (!filters.severity || finding.severity === filters.severity)
      && (!filters.file || finding.file === filters.file)
      && (!filters.cwe || finding.cwe?.id === filters.cwe)
      && (!filters.owasp || finding.owasp?.id === filters.owasp)
      && (!filters.principle || (finding.principles || []).includes(filters.principle))
      && (!filters.status || status === filters.status);
  });
  const severityWeight = { Critical: 1, High: 2, Medium: 3, Low: 4, Info: 5 };
  matches.sort((a, b) => {
    if (filters.sort === "line") return (Number(a.line) || 0) - (Number(b.line) || 0);
    if (filters.sort === "file") return String(a.file || "").localeCompare(String(b.file || ""));
    if (filters.sort === "priority") return (Number(a.priority) || 999) - (Number(b.priority) || 999);
    return (severityWeight[a.severity] || 6) - (severityWeight[b.severity] || 6);
  });
  const pageCount = Math.max(1, Math.ceil(matches.length / findingPageSize));
  findingPageIndex = Math.min(findingPageIndex, pageCount - 1);
  const visible = matches.slice(findingPageIndex * findingPageSize, (findingPageIndex + 1) * findingPageSize);
  const list = document.getElementById("findings-list");
  const count = document.getElementById("finding-count");
  if (list) list.innerHTML = visible.map(findingMarkup).join("") || '<div class="empty-state compact"><strong>No matching findings</strong><p>Clear filters or adjust the search to see results.</p></div>';
  if (count) count.textContent = `${matches.length} of ${activeFindings.length} finding(s)`;
  const pagination = document.getElementById("finding-pagination");
  if (pagination) {
    pagination.classList.toggle("hidden", matches.length <= findingPageSize);
    document.getElementById("finding-page").textContent = `Page ${findingPageIndex + 1} of ${pageCount}`;
    document.getElementById("finding-prev").disabled = findingPageIndex === 0;
    document.getElementById("finding-next").disabled = findingPageIndex >= pageCount - 1;
  }
  document.querySelectorAll("[data-review-status]").forEach(control => control.addEventListener("change", () => saveFindingReview(control.dataset.reviewStatus, { status: control.value })));
  document.querySelectorAll("[data-review-notes]").forEach(control => control.addEventListener("change", () => saveFindingReview(control.dataset.reviewNotes, { notes: control.value })));
}

function getFindingReviews() {
  try {
    return JSON.parse(localStorage.getItem("findingReviews") || "{}");
  } catch (error) {
    return {};
  }
}

function saveFindingReview(findingId, updates) {
  if (!findingId) return;
  try {
    const reviews = getFindingReviews();
    const now = new Date().toISOString();
    reviews[findingId] = {
      ...reviews[findingId],
      ...updates,
      created_at: reviews[findingId]?.created_at || now,
      modified_at: now,
    };
    localStorage.setItem("findingReviews", JSON.stringify(reviews));
    const latest = getStoredScan();
    if (latest) {
      const target = (latest.findings || []).find(finding => finding.finding_id === findingId);
      if (target) target.review = reviews[findingId];
      localStorage.setItem("lastScan", JSON.stringify(latest));
      window.lastScan = latest;
    }
  } catch (error) {
    setReportStatus("Unable to save finding review in browser storage.", true);
  }
}

function renderRisk(result) {
  if (!document.getElementById("risk-level") || !result) return;
  const risk = calculateRisk(result);
  document.getElementById("risk-level").textContent = risk;
  document.getElementById("risk-summary").textContent = result.total ? `${result.total} finding${result.total === 1 ? "" : "s"} detected in the latest analysis.` : "No configured patterns were detected.";
  renderSeverityCards(result.counts, "risk");
  const list = document.getElementById("risk-list");
  if (!list) return;
  const maximum = Math.max(...severityLevels.map(level => result.counts?.[level] || 0), 1);
  list.innerHTML = severityLevels.map(level => `<div class="risk-row"><span>${level}</span><div class="risk-bar"><span style="width:${((result.counts?.[level] || 0) / maximum) * 100}%"></span></div><strong>${result.counts?.[level] || 0}</strong></div>`).join("");
  const byCategory = new Map();
  (result.findings || []).forEach(finding => byCategory.set(finding.category || "Uncategorized", (byCategory.get(finding.category || "Uncategorized") || 0) + 1));
  const categories = document.getElementById("risk-categories");
  if (categories) categories.innerHTML = [...byCategory].map(([category, count]) => `<p><strong>${escapeHtml(category)}</strong><span>${count}</span></p>`).join("") || "No findings returned; this is not a security clearance.";
  const priorityList = document.getElementById("risk-priorities");
  if (priorityList) priorityList.innerHTML = [...(result.findings || [])]
    .sort((a, b) => (Number(a.priority) || 999) - (Number(b.priority) || 999))
    .slice(0, 5)
    .map(finding => `<p><span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span> ${escapeHtml(finding.title)} — ${escapeHtml(finding.file || "source.py")}:${escapeHtml(finding.line)}</p>`).join("") || "<p>No configured patterns were detected. Manual review remains necessary.</p>";
  const actions = document.getElementById("risk-actions");
  if (actions) actions.innerHTML = (result.findings || [])
    .filter(finding => ["Critical", "High"].includes(finding.severity))
    .slice(0, 5)
    .map(finding => `<li>${escapeHtml(finding.recommendation || "Review finding manually.")}</li>`).join("") || "<li>Continue manual review; no critical or high patterns were returned.</li>";
  const method = document.getElementById("risk-method");
  if (method && result.risk_method) method.textContent = result.risk_method;
}

function renderPrincipleCounts(result) {
  if (!result) return;
  document.querySelectorAll("[data-principle]").forEach(element => {
    const count = (result.findings || []).filter(finding => (finding.principles || []).includes(element.dataset.principle)).length;
    element.textContent = count;
  });
}

function renderAllStoredViews(result) {
  renderDashboard(result);
  renderFindings(result);
  renderRisk(result);
  renderPrincipleCounts(result);
}

function updateLineNumbers() {
  const editor = document.getElementById("code");
  const numbers = document.getElementById("line-numbers");
  if (!editor || !numbers) return;
  numbers.innerHTML = editor.value.split("\n").map((_, index) => `<span>${index + 1}</span>`).join("");
}

function setupInteractions() {
  const menu = document.querySelector(".menu-toggle");
  const nav = document.getElementById("primary-nav");
  menu?.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    menu.setAttribute("aria-expanded", String(open));
  });
  const editor = document.getElementById("code");
  editor?.addEventListener("input", updateLineNumbers);
  editor?.addEventListener("scroll", () => {
    const numbers = document.getElementById("line-numbers");
    if (numbers) numbers.scrollTop = editor.scrollTop;
  });
  document.getElementById("finding-search")?.addEventListener("input", () => {
    findingPageIndex = 0;
    updateFindingFilters();
  });
  ["finding-severity", "finding-file", "finding-cwe", "finding-owasp", "finding-principle", "finding-status", "finding-sort"].forEach(id => {
    document.getElementById(id)?.addEventListener("change", () => {
      findingPageIndex = 0;
      updateFindingFilters();
    });
  });
  document.getElementById("clear-finding-filters")?.addEventListener("click", () => {
    document.querySelectorAll(".finding-filter-grid input, .finding-filter-grid select").forEach(input => { input.value = ""; });
    findingPageIndex = 0;
    updateFindingFilters();
  });
  document.getElementById("finding-prev")?.addEventListener("click", () => { findingPageIndex -= 1; updateFindingFilters(); });
  document.getElementById("finding-next")?.addEventListener("click", () => { findingPageIndex += 1; updateFindingFilters(); });
  document.querySelectorAll("[data-scan-mode]").forEach(button => button.addEventListener("click", () => {
    const selectedMode = button.dataset.scanMode;
    document.getElementById("single-mode")?.classList.toggle("hidden", selectedMode !== "single");
    document.getElementById("project-mode")?.classList.toggle("hidden", selectedMode !== "project");
    document.getElementById("git-mode")?.classList.toggle("hidden", selectedMode !== "git");
    document.querySelectorAll("[data-scan-mode]").forEach(item => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
  }));
  const projectInput = document.getElementById("project-zip");
  document.getElementById("github-scan-button")?.addEventListener("click", scanGitHub);
  projectInput?.addEventListener("change", () => {
    const file = projectInput.files[0];
    document.getElementById("project-name").textContent = file ? `${file.name} (${Math.ceil(file.size / 1024)} KB)` : "No project selected";
    document.getElementById("project-scan-button").disabled = !file || !file.name.toLowerCase().endsWith(".zip") || file.size > 20 * 1024 * 1024;
    document.getElementById("project-status").textContent = file && file.size > 20 * 1024 * 1024 ? "ZIP archives must be 20 MB or smaller." : "";
  });
  const dropZone = document.getElementById("project-drop-zone");
  dropZone?.addEventListener("dragover", event => { event.preventDefault(); dropZone.classList.add("dragging"); });
  dropZone?.addEventListener("dragleave", () => dropZone.classList.remove("dragging"));
  dropZone?.addEventListener("drop", event => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
    const file = event.dataTransfer.files[0];
    if (!file) return;
    const transfer = new DataTransfer();
    transfer.items.add(file);
    projectInput.files = transfer.files;
    projectInput.dispatchEvent(new Event("change"));
  });
  initializeHistoryPage();
  initializeChecklistPage();
  initializeDependencyPage();
  renderScanHistory();
  document.querySelectorAll("[data-report-format]").forEach(button => button.addEventListener("click", () => {
    downloadReport(null, button.dataset.reportFormat);
  }));
  document.getElementById("report-scan")?.addEventListener("change", refreshReportAvailability);
  updateLineNumbers();
}

document.addEventListener("DOMContentLoaded", () => {
  setupInteractions();
  const result = getStoredScan();
  if (result) {
    (result.findings || []).forEach(finding => { finding.review = getFindingReviews()[finding.finding_id]; });
    window.lastScan = result;
  }
  refreshReportAvailability();
  if (document.getElementById("report-status") && result) {
    setReportStatus("A completed scan is available for PDF report generation.");
  }
  if (result) {
    renderAllStoredViews(result);
    if (document.getElementById("results")) renderScanResults(result);
  }
});
