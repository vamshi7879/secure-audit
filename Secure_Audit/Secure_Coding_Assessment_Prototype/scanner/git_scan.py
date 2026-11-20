from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
import re
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from http.client import HTTPException

from scanner.project_scan import ProjectArchiveError, scan_project_archive

MAX_REPOSITORY_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_GITHUB_RESPONSE_BYTES = 1024 * 1024
MAX_REPOSITORY_SCANS_PER_HOUR = 20
REQUEST_TIMEOUT_SECONDS = 5
_OWNER_OR_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_COMMIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_REQUEST_TIMES: deque[float] = deque()
_REQUEST_LOCK = threading.Lock()


class GitRepositoryError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _parse_github_url(repository_url: str) -> tuple[str, str, str | None]:
    if not isinstance(repository_url, str) or len(repository_url) > 2048:
        raise GitRepositoryError("Enter a valid public GitHub repository URL.")
    try:
        parsed = urlsplit(repository_url)
        port = parsed.port
    except ValueError as error:
        raise GitRepositoryError("The GitHub URL is malformed.") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitRepositoryError("Only plain HTTPS URLs on github.com are accepted; credentials, ports, query strings, and fragments are not allowed.")

    segments = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    if len(segments) < 2 or not _OWNER_OR_REPO.fullmatch(segments[0]):
        raise GitRepositoryError("Use a public GitHub URL in the form https://github.com/owner/repository.")
    owner, repo = segments[:2]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not repo or not _OWNER_OR_REPO.fullmatch(repo):
        raise GitRepositoryError("The GitHub repository name is invalid.")

    branch = None
    if len(segments) > 2:
        if len(segments) < 4 or segments[2] != "tree":
            raise GitRepositoryError("Use a repository URL or a branch URL ending in /tree/branch.")
        branch = "/".join(segments[3:])
        if (
            not _BRANCH.fullmatch(branch)
            or "\\" in branch
            or any(part in ("", ".", "..") for part in branch.split("/"))
        ):
            raise GitRepositoryError("The branch name contains unsupported path characters.")
    return owner, repo, branch


def _check_rate_limit() -> None:
    now = time.monotonic()
    with _REQUEST_LOCK:
        while _REQUEST_TIMES and now - _REQUEST_TIMES[0] >= 3600:
            _REQUEST_TIMES.popleft()
        if len(_REQUEST_TIMES) >= MAX_REPOSITORY_SCANS_PER_HOUR:
            raise GitRepositoryError("The local GitHub scan limit has been reached; try again later.", 429)
        _REQUEST_TIMES.append(now)


def _request_bytes(url: str, accept: str, limit: int) -> bytes:
    request = Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": "SecureCodeAudit/1.0",
        },
        method="GET",
    )
    opener = build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise GitRepositoryError("GitHub returned an unsuccessful response.", 502)
            body = response.read(limit + 1)
            if len(body) > limit:
                raise GitRepositoryError("The GitHub response exceeded the configured size limit.", 413)
            return body
    except HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            raise GitRepositoryError("GitHub returned a redirect; redirects are not followed for safety.", 502) from error
        if error.code == 404:
            raise GitRepositoryError("The public repository or requested branch was not found.", 404) from error
        if error.code == 403:
            raise GitRepositoryError("GitHub denied the request or its public API rate limit was reached.", 429) from error
        raise GitRepositoryError(f"GitHub returned HTTP {error.code}.", 502) from error
    except (URLError, HTTPException, TimeoutError, OSError) as error:
        raise GitRepositoryError("Unable to connect to GitHub; no source was scanned.", 502) from error


def _github_json(url: str) -> dict:
    body = _request_bytes(url, "application/vnd.github+json", MAX_GITHUB_RESPONSE_BYTES)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GitRepositoryError("GitHub returned invalid repository metadata.", 502) from error
    if not isinstance(data, dict):
        raise GitRepositoryError("GitHub returned repository metadata in an unexpected format.", 502)
    return data


def scan_github_repository(repository_url: str) -> dict:
    owner, repo, branch = _parse_github_url(repository_url)
    _check_rate_limit()
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    base_api_url = f"https://api.github.com/repos/{encoded_owner}/{encoded_repo}"
    if branch is None:
        repository = _github_json(base_api_url)
        branch = repository.get("default_branch")
        if not isinstance(branch, str) or not _BRANCH.fullmatch(branch) or ".." in branch.split("/"):
            raise GitRepositoryError("GitHub did not return a usable default branch.", 502)

    encoded_branch = quote(branch, safe="/")
    commit = _github_json(f"{base_api_url}/commits/{encoded_branch}")
    commit_sha = commit.get("sha")
    if not isinstance(commit_sha, str) or not _COMMIT_SHA.fullmatch(commit_sha):
        raise GitRepositoryError("GitHub did not return a valid commit identifier.", 502)

    archive_url = f"https://codeload.github.com/{encoded_owner}/{encoded_repo}/zip/{commit_sha}"
    archive_data = _request_bytes(archive_url, "application/zip", MAX_REPOSITORY_ARCHIVE_BYTES)
    try:
        result = scan_project_archive(archive_data, f"{owner}-{repo}.zip")
    except ProjectArchiveError as error:
        raise GitRepositoryError(f"The downloaded repository archive could not be safely scanned: {error}") from error

    result.update({
        "scan_type": "git",
        "project_name": f"{owner}/{repo}",
        "analyzed_filename": f"{owner}/{repo}@{branch}",
        "repository_url": f"https://github.com/{encoded_owner}/{encoded_repo}/tree/{encoded_branch}",
        "branch": branch,
        "commit_sha": commit_sha.lower(),
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    return result
