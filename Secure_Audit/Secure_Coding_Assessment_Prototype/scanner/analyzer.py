import ast
from scanner.command_injection import check_command_injection
from scanner.path_traversal import check_path_traversal
from scanner.password_storage import check_password_storage
from scanner.exception_handling import check_exception_handling
from scanner.temp_file import check_predictable_temp_files
from scanner.dependencies import check_dependencies
from scanner.configuration import check_secure_configuration

CHECKS = [
    check_command_injection,
    check_path_traversal,
    check_password_storage,
    check_exception_handling,
    check_predictable_temp_files,
    check_dependencies,
    check_secure_configuration,
]

def analyze_code(code: str):
    findings = []
    syntax_error = None
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        tree = None
        syntax_error = f"Syntax error at line {exc.lineno}: {exc.msg}"

    if tree is not None:
        for check in CHECKS:
            findings.extend(check(tree, code))

    priority = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}
    findings.sort(key=lambda x: (priority.get(x["severity"], 9), x["line"]))

    counts = {level: sum(1 for f in findings if f["severity"] == level)
              for level in ["Critical", "High", "Medium", "Low", "Info"]}

    return {
        "findings": findings,
        "counts": counts,
        "total": len(findings),
        "syntax_error": syntax_error,
        "summary": build_summary(findings)
    }

def build_summary(findings):
    if any(f["severity"] == "Critical" for f in findings):
        return "Immediate remediation should focus on critical attack-surface weaknesses."
    if any(f["severity"] == "High" for f in findings):
        return "High-impact weaknesses should be addressed before lower-risk improvements."
    if findings:
        return "Security improvements are recommended before production deployment."
    return "No configured patterns were detected; manual review is still required."
