from scanner.mappings import RULES

RISK_METHOD = (
    "Categorical highest-severity model: Critical takes precedence over High, then Medium, "
    "otherwise Low. No numeric score is calculated. A Low result or zero findings does not "
    "mean the project is secure; only configured static patterns were evaluated."
)


def risk_level(findings: list[dict]) -> str:
    severities = {finding.get("severity") for finding in findings}
    for severity in ("Critical", "High", "Medium"):
        if severity in severities:
            return severity
    return "Low"


def checklist_results(findings: list[dict], syntax_error: bool = False) -> list[dict]:
    results = []
    for rule in RULES:
        matching = [finding for finding in findings if finding.get("rule_id", finding.get("id")) == rule["id"]]
        if syntax_error:
            status = "Not Assessed"
            evidence = "Source could not be parsed; this AST check did not run."
        elif matching:
            status = "Fail"
            evidence = "; ".join(
                f"{finding.get('file', 'source.py')}:{finding.get('line', 'Not available')} — {finding.get('title', rule['id'])}"
                for finding in matching[:5]
            )
        elif rule["id"] == "DEP-001":
            status = "Not Assessed"
            evidence = "No dependency advisory lookup is included in the source-code scan."
        else:
            status = "Not Assessed"
            evidence = "The static rule reported no matching pattern. Absence of a finding is not evidence that the control passes."
        results.append({
            "rule_id": rule["id"],
            "category": rule["category"],
            "check": rule["description"],
            "status": status,
            "evidence": evidence,
            "related_findings": [finding.get("finding_id") for finding in matching],
            "recommendation": rule["recommendation"],
            "principle": rule["principle"],
        })
    return results
