# Implementation Notes

## Implemented stages

1. **Project scanning:** in-memory bounded ZIP inspection, per-file attribution, findings search/filter/sort/pagination.
2. **Mappings and checklist:** rule IDs with tentative CWE/OWASP associations; checklist states do not infer Pass from a missing finding.
3. **Exports:** ReportLab PDF, CSV and JSON; optional report filters; PDF font selection and fallback are documented; CSV formula-like values are escaped.
4. **Risk and tracking:** highest-severity categorical risk (no numeric score), browser-local history, remediation statuses/notes, and explicit not-detected tracking.
5. **Dependency/configuration review:** AST checks for selected configuration patterns and explicit OSV queries for exact pinned Python dependencies.
6. **Git integration and tests:** restricted public GitHub scanning pinned to a commit SHA, alongside automated scanner, endpoint, dependency, export and report tests.

## Security boundaries

- Python source is parsed as text only; no source file or dependency is executed or installed.
- ZIP and GitHub archive inputs are processed in memory, not extracted. Paths, symlinks, archive sizes, entry counts, file sizes, total source size, timeouts, redirects and supported hosts are constrained.
- GitHub scanning accepts only public `github.com` repository URLs and fetches only from fixed GitHub API/archive hosts. It does not support private repositories, user credentials, GitLab, or arbitrary URLs.
- Dependency auditing calls only the fixed OSV.dev batch endpoint after the user explicitly starts an audit. It does not follow user-provided URLs.
- Browser history/remediation state is local to the browser and is not a persistent server-side database.
- A clean scan or no advisory response is not a pass, proof of safety, exploitability assessment, or compliance certification.
