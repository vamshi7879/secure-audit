import ast

def check_password_storage(tree, code):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target_nodes = node.targets if isinstance(node, ast.Assign) else [node.target]
            targets = [t.id.lower() for t in target_nodes if isinstance(t, ast.Name)]
            if any("password" in t or t in {"passwd", "pwd"} for t in targets):
                findings.append({
                    "id": "AUTH-001",
                    "category": "Plaintext Password Storage",
                    "severity": "High",
                    "priority": 3,
                    "line": node.lineno,
                    "title": "Password value may be stored or handled without hashing",
                    "description": "Static analysis indicates that a password value may be stored or handled without a password-hashing operation. Manual review is required.",
                    "impact": "Plaintext credentials can expose users broadly after a database, log, or backup disclosure.",
                    "recommendation": "Never store plaintext passwords. Use a password-hashing function designed for password storage such as Argon2id, bcrypt, or scrypt and verify hashes during authentication.",
                    "secure_example": "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
                    "principles": ["Secure Data Storage", "Defense in Depth"]
                })
    return findings
