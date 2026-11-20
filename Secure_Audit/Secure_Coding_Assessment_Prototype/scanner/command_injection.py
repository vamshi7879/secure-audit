import ast

def check_command_injection(tree, code):
    findings = []
    dangerous = {"system", "popen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            shell_true = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
            if node.func.attr in dangerous or (node.func.attr in {"run", "call", "check_call", "check_output", "Popen"} and shell_true):
                connected = any(isinstance(child, (ast.JoinedStr, ast.BinOp, ast.Name)) for child in ast.walk(node) if child is not node)
                findings.append({
                    "id": "CMD-001",
                    "category": "Command Injection",
                    "severity": "Critical" if connected else "High",
                    "priority": 1,
                    "line": node.lineno,
                    "title": "Potential OS command execution",
                    "description": "Potential command injection risk detected. A shell/process API receives a dynamic value; manual data-flow review is required.",
                    "impact": "If attacker-controlled input reaches a shell command, unintended operating-system commands may execute.",
                    "recommendation": "Avoid shell command construction. Prefer subprocess with a fixed argument list, strict validation, and least privilege.",
                    "secure_example": 'subprocess.run(["ping", "-c", "1", validated_host], check=True)',
                    "principles": ["Input Validation", "Least Privilege", "Defense in Depth", "Minimize Attack Surface"]
                })
    return findings
