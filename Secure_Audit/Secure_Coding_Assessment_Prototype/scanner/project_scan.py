from __future__ import annotations

from io import BytesIO
from pathlib import PurePosixPath
import stat
import zipfile
import zlib

from scanner.analyzer import analyze_code
from scanner.mappings import add_finding_metadata, finding_identifier

MAX_ARCHIVE_FILES = 1000
MAX_PYTHON_FILES = 300
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_PYTHON_BYTES = 25 * 1024 * 1024


class ProjectArchiveError(ValueError):
    pass


def scan_project_archive(archive_data: bytes, archive_name: str = "project.zip") -> dict:
    if not archive_data:
        raise ProjectArchiveError("The uploaded project archive is empty.")
    supported_files: list[tuple[str, zipfile.ZipInfo]] = []
    skipped_files: list[str] = []
    seen_paths: set[str] = set()
    total_python_bytes = 0

    try:
        archive = zipfile.ZipFile(BytesIO(archive_data))
    except (zipfile.BadZipFile, OSError) as error:
        raise ProjectArchiveError("The uploaded file is not a valid ZIP archive.") from error

    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_ARCHIVE_FILES:
            raise ProjectArchiveError(f"The archive contains too many entries (maximum {MAX_ARCHIVE_FILES}).")

        for entry in entries:
            original_name = entry.filename
            if not original_name or "\\" in original_name:
                raise ProjectArchiveError("The archive contains an unsafe file path.")
            path = PurePosixPath(original_name)
            if not path.parts or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts) or ":" in path.parts[0]:
                raise ProjectArchiveError("The archive contains an unsafe file path.")
            normalized = path.as_posix()
            if normalized in seen_paths:
                raise ProjectArchiveError("The archive contains duplicate file paths.")
            seen_paths.add(normalized)

            unix_mode = entry.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                raise ProjectArchiveError("Symbolic links are not supported in project archives.")
            if entry.is_dir():
                continue
            if path.suffix.lower() != ".py":
                skipped_files.append(normalized)
                continue
            if entry.flag_bits & 0x1:
                raise ProjectArchiveError("Encrypted project archives are not supported.")
            if entry.file_size > MAX_FILE_BYTES:
                raise ProjectArchiveError(f"A Python source file exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB per-file limit.")
            supported_files.append((normalized, entry))

        if not supported_files:
            raise ProjectArchiveError("The archive contains no supported Python (.py) source files.")
        if len(supported_files) > MAX_PYTHON_FILES:
            raise ProjectArchiveError(f"The archive contains too many Python files (maximum {MAX_PYTHON_FILES}).")

        findings = []
        file_results = []
        for filename, entry in supported_files:
            try:
                with archive.open(entry) as member:
                    source_bytes = member.read(MAX_FILE_BYTES + 1)
                if len(source_bytes) > MAX_FILE_BYTES:
                    raise ProjectArchiveError(f"A Python source file exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB per-file limit.")
                total_python_bytes += len(source_bytes)
                if total_python_bytes > MAX_TOTAL_PYTHON_BYTES:
                    raise ProjectArchiveError("The combined Python source exceeds the project size limit.")
                source = source_bytes.decode("utf-8")
            except ProjectArchiveError:
                raise
            except (UnicodeDecodeError, RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError, zlib.error, ValueError) as error:
                raise ProjectArchiveError(f"Unable to read Python source file: {filename}") from error
            result = analyze_code(source)
            file_results.append({
                "file": filename,
                "syntax_error": result["syntax_error"],
                "findings": len(result["findings"]),
            })
            for finding in result["findings"]:
                decorated = add_finding_metadata(finding, filename)
                decorated["finding_id"] = finding_identifier(decorated)
                findings.append(decorated)

    counts = {
        severity: sum(finding.get("severity") == severity for finding in findings)
        for severity in ("Critical", "High", "Medium", "Low", "Info")
    }
    return {
        "scan_type": "project",
        "project_name": PurePosixPath(archive_name.replace("\\", "/")).stem or "project",
        "analyzed_filename": PurePosixPath(archive_name.replace("\\", "/")).name or "project.zip",
        "files_analyzed": [item["file"] for item in file_results],
        "files_supported": len(file_results),
        "files_skipped": skipped_files,
        "file_results": file_results,
        "findings": findings,
        "counts": counts,
        "total": len(findings),
        "syntax_errors": sum(item["syntax_error"] is not None for item in file_results),
        "summary": f"Analyzed {len(file_results)} Python file(s); {len(findings)} finding(s) returned.",
    }
