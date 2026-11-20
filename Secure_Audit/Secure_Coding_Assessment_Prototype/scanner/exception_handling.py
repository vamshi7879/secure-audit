import ast

def check_exception_handling(tree, code):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append({
                "id": "ERR-001",
                "category": "Generic Exception Handling",
                "severity": "Medium",
                "priority": 5,
                "line": node.lineno,
                "title": "Bare except clause",
                "description": "A bare except catches nearly every exception and can hide programming and security failures.",
                "impact": "Hidden failures can leave the application in an unsafe or inconsistent state and make incident investigation harder.",
                "recommendation": "Catch specific expected exceptions, log appropriate security-relevant events, and fail safely.",
                "secure_example": "except ValueError:\n    logger.warning('Invalid input')",
                "principles": ["Secure Failure", "Least Privilege", "Defense in Depth"]
            })
    return findings
