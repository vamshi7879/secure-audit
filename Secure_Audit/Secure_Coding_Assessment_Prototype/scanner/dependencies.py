import ast

def check_dependencies(tree, code):
    findings = []
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module.split(".")[0])
    if imports:
        findings.append({
            "id": "DEP-001",
            "category": "Dependency Management",
            "severity": "Medium",
            "priority": 6,
            "line": 1,
            "title": "External dependency review required",
            "description": "Imported libraries should be inventoried and checked regularly for known vulnerabilities and unnecessary exposure.",
            "impact": "An unmaintained dependency may introduce known vulnerabilities or unnecessary attack surface.",
            "recommendation": "Maintain a requirements/lock file, update dependencies, remove unused packages, and use automated vulnerability auditing in CI.",
            "secure_example": "Run dependency auditing in CI and review advisories before upgrading.",
            "principles": ["Minimize Attack Surface", "Secure Maintenance", "Defense in Depth"]
        })
    return findings
