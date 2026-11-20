import ast

def check_path_traversal(tree, code):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant):
                    findings.append({
                        "id": "PATH-001",
                        "category": "Unsafe File Access / Path Traversal",
                        "severity": "Critical",
                        "priority": 2,
                        "line": node.lineno,
                        "title": "Potentially user-controlled file path",
                        "description": "open() receives a non-constant path expression. If that value is user-controlled, files outside the intended directory may be accessed.",
                        "impact": "An attacker may read or overwrite files outside the intended application directory.",
                        "recommendation": "Use an allowlist, constrain access to a trusted base directory, resolve paths safely, and reject paths outside that directory.",
                        "secure_example": "candidate = (BASE_DIR / name).resolve()\nif BASE_DIR not in candidate.parents:\n    raise ValueError('Invalid path')",
                        "principles": ["Input Validation", "Least Privilege", "Defense in Depth"]
                    })
    return findings
