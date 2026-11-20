from pathlib import Path
import subprocess
import tempfile

BASE_DIR = Path("/srv/app/uploads").resolve()

def safe_file(name):
    candidate = (BASE_DIR / name).resolve()
    if BASE_DIR not in candidate.parents and candidate != BASE_DIR:
        raise ValueError("Invalid file path")
    return candidate

def ping_host(host):
    # In production, validate against a strict allowlist appropriate to the use case.
    return subprocess.run(["ping", "-c", "1", host], check=True, capture_output=True, text=True)

def create_temp():
    return tempfile.NamedTemporaryFile(prefix="report_", delete=False)
