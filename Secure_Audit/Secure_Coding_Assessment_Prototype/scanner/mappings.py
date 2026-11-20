RULE_METADATA = {
    "CMD-001": {
        "cwe": {"id": "CWE-78", "title": "Improper Neutralization of Special Elements used in an OS Command", "confidence": "high"},
        "owasp": {"id": "A03:2021", "title": "Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/", "confidence": "high"},
    },
    "PATH-001": {
        "cwe": {"id": "CWE-73", "title": "External Control of File Name or Path", "confidence": "review"},
        "owasp": None,
    },
    "PASS-001": {
        "cwe": {"id": "CWE-256", "title": "Plaintext Storage of a Password", "confidence": "review"},
        "owasp": {"id": "A02:2021", "title": "Cryptographic Failures", "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/", "confidence": "review"},
    },
    "EXC-001": {
        "cwe": {"id": "CWE-396", "title": "Declaration of Catch for Generic Exception", "confidence": "review"},
        "owasp": None,
    },
    "TEMP-001": {
        "cwe": {"id": "CWE-377", "title": "Insecure Temporary File", "confidence": "review"},
        "owasp": None,
    },
    "DEP-001": {
        "cwe": None,
        "owasp": {"id": "A06:2021", "title": "Vulnerable and Outdated Components", "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/", "confidence": "review"},
    },
    "CONFIG-SECRET-001": {
        "cwe": {"id": "CWE-798", "title": "Use of Hard-coded Credentials", "confidence": "review"},
        "owasp": None,
    },
    "CONFIG-COOKIE-001": {
        "cwe": {"id": "CWE-614", "title": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "confidence": "review"},
        "owasp": None,
    },
    "CONFIG-DEBUG-001": {"cwe": None, "owasp": None},
    "CONFIG-CORS-001": {
        "cwe": {"id": "CWE-942", "title": "Permissive Cross-domain Policy with Untrusted Domains", "confidence": "review"},
        "owasp": {
            "id": "A05:2021",
            "title": "Security Misconfiguration",
            "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "confidence": "review",
        },
    },
}

RULES = [
    {
        "id": "CMD-001",
        "category": "Command Execution",
        "description": "Detects selected process APIs invoked in a way that may use dynamic values or a shell.",
        "recommendation": "Review each reported process invocation; no finding does not establish that all command execution is safe.",
        "principle": "Input Validation",
    },
    {
        "id": "PATH-001",
        "category": "File Access",
        "description": "Detects open() calls whose path argument is not a literal constant.",
        "recommendation": "Review data flow and constrain paths to an explicitly trusted base directory.",
        "principle": "Least Privilege",
    },
    {
        "id": "PASS-001",
        "category": "Credential Storage",
        "description": "Detects selected password-like values stored or handled without a recognized hashing operation.",
        "recommendation": "Manually verify password handling and use a dedicated password hashing scheme.",
        "principle": "Secure Data Storage",
    },
    {
        "id": "EXC-001",
        "category": "Exception Handling",
        "description": "Detects bare except clauses in Python syntax trees.",
        "recommendation": "Catch only expected exceptions and handle failures explicitly.",
        "principle": "Secure Failure",
    },
    {
        "id": "TEMP-001",
        "category": "Temporary File Security",
        "description": "Detects selected predictable temporary path patterns.",
        "recommendation": "Use tempfile APIs that create unpredictable files with safe permissions.",
        "principle": "Secure Defaults",
    },
    {
        "id": "DEP-001",
        "category": "Dependency Management",
        "description": "Indicates dependency review is needed; it does not query vulnerability advisories.",
        "recommendation": "Review pinned dependencies using an advisory source such as OSV.",
        "principle": "Minimize Attack Surface",
    },
    {
        "id": "CONFIG-DEBUG-001",
        "category": "Secure Configuration",
        "description": "Detects literal True assignments to recognized DEBUG settings in Python source.",
        "recommendation": "Review deployment settings; this source pattern does not establish that debug mode is active in production.",
        "principle": "Secure Defaults",
    },
    {
        "id": "CONFIG-COOKIE-001",
        "category": "Secure Configuration",
        "description": "Detects literal False assignments to recognized secure-cookie settings.",
        "recommendation": "Review HTTPS deployment and cookie settings.",
        "principle": "Secure Defaults",
    },
    {
        "id": "CONFIG-CORS-001",
        "category": "Secure Configuration",
        "description": "Detects wildcard values in recognized CORS-origin settings.",
        "recommendation": "Review application endpoints, credential behavior, and intended origin allowlists.",
        "principle": "Least Privilege",
    },
    {
        "id": "CONFIG-SECRET-001",
        "category": "Secure Configuration",
        "description": "Detects non-placeholder string literals assigned to recognized secret-like setting names; literal values are redacted.",
        "recommendation": "Review whether the literal is a real credential, remove it from source, and rotate it if exposed.",
        "principle": "Secure Data Storage",
    },
]


def add_finding_metadata(finding: dict, filename: str) -> dict:
    rule_id = finding.get("id")
    mapping = RULE_METADATA.get(rule_id, {"cwe": None, "owasp": None})
    return {
        **finding,
        "rule_id": rule_id or "UNMAPPED",
        "file": filename,
        "cwe": mapping["cwe"],
        "owasp": mapping["owasp"],
        "mapping_status": "review_required" if mapping["cwe"] or mapping["owasp"] else "unavailable",
        "status": finding.get("status", "Open"),
    }


def finding_identifier(finding: dict) -> str:
    import hashlib

    identity = "\0".join(str(finding.get(key, "")) for key in ("rule_id", "file", "line", "title"))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
