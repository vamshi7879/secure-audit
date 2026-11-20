from __future__ import annotations

import ast

_PLACEHOLDERS = {"", "changeme", "change_me", "example", "placeholder", "your-secret-here"}


def _setting_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id.upper()
    if isinstance(target, ast.Attribute):
        return target.attr.upper()
    if isinstance(target, ast.Subscript):
        key = target.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value.upper()
    return None


def _literal_value(value: ast.expr):
    if isinstance(value, ast.Constant):
        return value.value
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return [_literal_value(item) for item in value.elts]
    return None


def check_secure_configuration(tree: ast.AST, code: str = "") -> list[dict]:
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                name = _setting_name(target)
                literal = _literal_value(value) if value is not None else None
                if name in {"DEBUG", "FLASK_DEBUG"} and literal is True:
                    findings.append({
                        "id": "CONFIG-DEBUG-001",
                        "category": "Secure Configuration",
                        "severity": "High",
                        "priority": 1,
                        "line": node.lineno,
                        "title": "Debug mode explicitly enabled",
                        "description": "A recognized debug setting is explicitly assigned True. Deployment context is not available to this static check.",
                        "impact": "If active in a deployed environment, debug behavior may disclose diagnostic details.",
                        "recommendation": "Disable debug mode for deployment and set it through trusted environment-specific configuration.",
                        "principles": ["Secure Defaults", "Defense in Depth"],
                        "review_required": True,
                    })
                if name in {"SESSION_COOKIE_SECURE", "COOKIE_SECURE"} and literal is False:
                    findings.append({
                        "id": "CONFIG-COOKIE-001",
                        "category": "Secure Configuration",
                        "severity": "Medium",
                        "priority": 2,
                        "line": node.lineno,
                        "title": "Secure cookie flag explicitly disabled",
                        "description": "A recognized secure-cookie setting is explicitly assigned False.",
                        "impact": "Cookies may be transmitted over unencrypted connections if the application is accessed over HTTP.",
                        "recommendation": "Enable the Secure cookie flag in production and validate HTTPS deployment behavior.",
                        "principles": ["Secure Defaults", "Secure Data Storage"],
                        "review_required": True,
                    })
                if name in {"CORS_ORIGINS", "CORS_ALLOW_ORIGINS", "ALLOWED_ORIGINS"}:
                    origins = literal if isinstance(literal, list) else [literal]
                    if "*" in origins:
                        findings.append({
                            "id": "CONFIG-CORS-001",
                            "category": "Secure Configuration",
                            "severity": "High",
                            "priority": 2,
                            "line": node.lineno,
                            "title": "Wildcard CORS origin explicitly configured",
                            "description": "A recognized origin setting contains the literal wildcard origin. Whether credentials or sensitive endpoints are involved requires review.",
                            "impact": "A permissive cross-origin policy may expose application responses to untrusted sites.",
                            "recommendation": "Use an explicit allowlist of trusted origins and review credential handling.",
                            "principles": ["Secure Defaults", "Least Privilege"],
                            "review_required": True,
                        })
                if name in {"SECRET_KEY", "API_KEY", "TOKEN", "PASSWORD"} and isinstance(literal, str):
                    if len(literal) >= 8 and literal.strip().lower() not in _PLACEHOLDERS:
                        findings.append({
                            "id": "CONFIG-SECRET-001",
                            "category": "Secure Configuration",
                            "severity": "High",
                            "priority": 1,
                            "line": node.lineno,
                            "title": "Potential hard-coded secret",
                            "description": "A string literal is assigned to a recognized secret-like setting. The value is intentionally withheld from report output.",
                            "impact": "A committed credential may be exposed to users of the source repository and reused outside the application.",
                            "recommendation": "Remove the literal, rotate the credential if real, and load secrets from a protected deployment secret store.",
                            "principles": ["Secure Data Storage", "Secure Defaults"],
                            "review_required": True,
                        })
    return findings
