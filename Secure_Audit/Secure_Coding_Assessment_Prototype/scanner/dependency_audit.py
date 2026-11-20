from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from http.client import HTTPException
import json
import re
import threading
import time
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_PACKAGES = 100
CACHE_TTL_SECONDS = 3600
MAX_OSV_QUERIES_PER_MINUTE = 10
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()
_QUERY_TIMES: deque[float] = deque()
_PACKAGE_LINE = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(===|==|~=|!=|<=|>=|<|>)?\s*([^\s;]+)?")
_PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(text: str) -> list[dict]:
    packages = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(("-", "--")):
            continue
        line = line.split(";", 1)[0].strip()
        match = _PACKAGE_LINE.match(line)
        if not match:
            packages.append({"package": line[:120], "version": None, "status": "Unable to parse dependency specification"})
            continue
        name, operator, version = match.groups()
        if "@" in line or not operator or operator not in ("==", "===") or not version or not _PIN.fullmatch(version):
            packages.append({"package": name, "version": None, "status": "Exact pinned version required for vulnerability lookup"})
            continue
        packages.append({"package": name, "version": version, "status": "Ready to check"})
    return packages


def _parse_pyproject(text: str) -> list[dict]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError("The pyproject.toml file is not valid TOML.") from error
    project = data.get("project", {})
    if not isinstance(project, dict):
        raise ValueError("The pyproject.toml project section must be a table.")
    project_dependencies = project.get("dependencies", [])
    if not isinstance(project_dependencies, list) or any(not isinstance(item, str) for item in project_dependencies):
        raise ValueError("The pyproject.toml project.dependencies value must be an array of strings.")
    package_specs = list(project_dependencies)
    optional_dependencies = project.get("optional-dependencies", {})
    if not isinstance(optional_dependencies, dict):
        raise ValueError("The pyproject.toml optional-dependencies value must be a table.")
    for specifications in optional_dependencies.values():
        if not isinstance(specifications, list) or any(not isinstance(item, str) for item in specifications):
            raise ValueError("The pyproject.toml optional dependencies must be arrays of strings.")
        package_specs.extend(specifications)

    tool = data.get("tool", {})
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    dependency_tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})] if isinstance(poetry, dict) else []
    groups = poetry.get("group", {}) if isinstance(poetry, dict) else {}
    if isinstance(groups, dict):
        dependency_tables.extend(
            group.get("dependencies", {})
            for group in groups.values()
            if isinstance(group, dict)
        )
    for dependency_table in dependency_tables:
        if not isinstance(dependency_table, dict):
            continue
        for name, specification in dependency_table.items():
            if name.lower() == "python":
                continue
            if isinstance(specification, str):
                package_specs.append(f"{name} {specification}")
            elif isinstance(specification, dict) and isinstance(specification.get("version"), str):
                package_specs.append(f"{name} {specification['version']}")
            else:
                package_specs.append(str(name))
    return _parse_requirements("\n".join(str(spec) for spec in package_specs))


def _osv_query(packages: list[dict]) -> tuple[dict | None, str | None]:
    key = json.dumps([(item["package"], item["version"]) for item in packages], sort_keys=True)
    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached and now - cached[0] < CACHE_TTL_SECONDS:
            return cached[1], None
        while _QUERY_TIMES and now - _QUERY_TIMES[0] >= 60:
            _QUERY_TIMES.popleft()
        if len(_QUERY_TIMES) >= MAX_OSV_QUERIES_PER_MINUTE:
            return None, "The local OSV query limit has been reached; retry later."
        _QUERY_TIMES.append(now)

    payload = {
        "queries": [
            {"package": {"name": _normalize(item["package"]), "ecosystem": "PyPI"}, "version": item["version"]}
            for item in packages
        ]
    }
    request = Request(
        OSV_QUERY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "SecureCodeAudit/1.0"},
        method="POST",
    )
    try:
        opener = build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=5) as response:
            if response.status != 200:
                return None, "OSV returned an unsuccessful response."
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                return None, "OSV response exceeded the size limit."
            data = json.loads(body.decode("utf-8"))
    except HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            return None, "OSV redirected the request; redirects are not followed for safety."
        return None, "Unable to check against OSV; no safety conclusion can be drawn."
    except (URLError, HTTPException, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "Unable to check against OSV; no safety conclusion can be drawn."
    if (not isinstance(data, dict) or not isinstance(data.get("results"), list)
            or len(data["results"]) != len(packages)
            or any(not isinstance(item, dict) for item in data["results"])):
        return None, "OSV response was not in the expected format."
    with _CACHE_LOCK:
        _CACHE[key] = (now, data)
    return data, None


def audit_manifest(text: str, filename: str) -> dict:
    encoded_size = len(text.encode("utf-8"))
    if encoded_size > MAX_MANIFEST_BYTES:
        raise ValueError("The dependency manifest exceeds the 1 MB limit.")
    lower_name = filename.lower()
    if lower_name.endswith("requirements.txt"):
        packages = _parse_requirements(text)
    elif lower_name.endswith("pyproject.toml"):
        packages = _parse_pyproject(text)
    else:
        raise ValueError("Only requirements.txt and pyproject.toml are supported.")
    if len(packages) > MAX_PACKAGES:
        raise ValueError(f"Manifest contains too many dependencies (maximum {MAX_PACKAGES}).")

    pinned = [item for item in packages if item["status"] == "Ready to check"]
    lookup_error = None
    osv_data = None
    if pinned:
        osv_data, lookup_error = _osv_query(pinned)
    osv_results = osv_data.get("results", []) if osv_data else []
    results = []
    pinned_index = 0
    for item in packages:
        result = {
            "package": item["package"],
            "version": item["version"],
            "status": item["status"],
            "source": "OSV.dev (public vulnerability database)",
            "last_checked": datetime.now(timezone.utc).isoformat(timespec="seconds") if item in pinned else None,
        }
        if item not in pinned:
            result["recommendation"] = "Pin a supported exact version before an advisory lookup; dependency was not marked safe."
            results.append(result)
            continue
        if lookup_error:
            result["status"] = "Unable to check"
            result["details"] = lookup_error
            result["recommendation"] = "Retry the OSV lookup; no safety conclusion can be drawn."
            pinned_index += 1
            results.append(result)
            continue
        package_result = osv_results[pinned_index] if pinned_index < len(osv_results) else {}
        pinned_index += 1
        vulnerabilities = package_result.get("vulns", []) if isinstance(package_result, dict) else []
        if not vulnerabilities:
            result["status"] = "No known vulnerabilities found"
            result["recommendation"] = "No advisory was returned for this exact version; this is not a guarantee of safety."
            results.append(result)
            continue
        for vulnerability in vulnerabilities:
            fixed_versions = []
            affected_ranges = []
            for affected in vulnerability.get("affected", []):
                for version_range in affected.get("ranges", []):
                    events = version_range.get("events", [])
                    introduced = [event["introduced"] for event in events if "introduced" in event]
                    fixed_versions.extend(event["fixed"] for event in events if "fixed" in event)
                    if introduced:
                        affected_ranges.append(f"introduced {introduced[0]}")
            result_copy = {
                **result,
                "status": "Vulnerability reported",
                "vulnerability_id": vulnerability.get("id", "Not available"),
                "details": vulnerability.get("summary") or vulnerability.get("details", "OSV advisory details unavailable."),
                "severity": "Not provided by OSV",
                "cvss": vulnerability.get("severity", []),
                "affected_range": "; ".join(affected_ranges) if affected_ranges else "Not available",
                "fixed_version": ", ".join(sorted(set(fixed_versions))) if fixed_versions else "Not provided",
                "recommendation": "Review the linked OSV advisory and update to a version outside the affected range; verify the fix before release.",
                "references": [
                    ref.get("url") for ref in vulnerability.get("references", [])
                    if ref.get("url", "").startswith("https://")
                ],
            }
            results.append(result_copy)

    if not packages:
        status = "No dependencies found in supported manifest"
    elif lookup_error and pinned:
        status = "Unable to check some or all pinned dependencies"
    elif any(item["status"] == "Vulnerability reported" for item in results):
        status = "Vulnerabilities reported"
    elif any(item["status"] != "No known vulnerabilities found" for item in results):
        status = "Some dependencies not assessed"
    else:
        status = "OSV lookup completed"
    return {
        "status": status,
        "manifest": filename,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "OSV.dev",
        "results": results,
    }
