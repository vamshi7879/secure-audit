import ast

def check_predictable_temp_files(tree, code):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                value = node.value.value
                if "/tmp/" in value or "\\\\temp\\\\" in value.lower():
                    findings.append({
                        "id": "TMP-001",
                        "category": "Predictable Temporary File",
                        "severity": "High",
                        "priority": 4,
                        "line": node.lineno,
                        "title": "Predictable temporary filename/path",
                        "description": "A hard-coded temporary location or filename can cause collisions or insecure file handling.",
                        "impact": "Predictable temporary names can cause collisions, race conditions, or unauthorized access to temporary data.",
                        "recommendation": "Use Python's tempfile module to create securely randomized temporary files and directories.",
                        "secure_example": "with tempfile.NamedTemporaryFile() as temporary_file:\n    temporary_file.write(data)",
                        "principles": ["Secure Defaults", "Defense in Depth", "Least Privilege"]
                    })
    return findings
