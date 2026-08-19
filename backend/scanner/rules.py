SQL_INJECTION_RULE = {
    "id": "PY-SQL-001",
    "name": "Potential SQL Injection",
    "severity": "HIGH",
    "description": (
        "A database query may be constructed using untrusted input "
        "before being passed to an SQL execution function."
    ),
    "recommendation": (
        "Use parameterized queries instead of string concatenation "
        "or string formatting when constructing SQL statements."
    ),
}


def create_sql_injection_finding(
    file_path: str,
    line_number: int,
    evidence: str,
) -> dict:
    """
    Create a standardized SQL injection security finding.
    """

    return {
        "rule_id": SQL_INJECTION_RULE["id"],
        "type": "sql_injection",
        "name": SQL_INJECTION_RULE["name"],
        "severity": SQL_INJECTION_RULE["severity"],
        "file": file_path,
        "line": line_number,
        "evidence": evidence,
        "description": SQL_INJECTION_RULE["description"],
        "recommendation": SQL_INJECTION_RULE["recommendation"],
    }


COMMAND_INJECTION_RULE = {
    "id": "PY-CMD-001",
    "name": "Potential Command Injection",
    "severity": "CRITICAL",
    "description": (
        "A system command may be constructed using untrusted input "
        "before being executed."
    ),
    "recommendation": (
        "Avoid passing untrusted input to system command execution. "
        "Use safe APIs, validate input, and avoid shell=True when possible."
    ),
}


def create_command_injection_finding(
    file_path: str,
    line_number: int,
    evidence: str,
) -> dict:
    """
    Create a standardized command injection security finding.
    """

    return {
        "rule_id": COMMAND_INJECTION_RULE["id"],
        "type": "command_injection",
        "name": COMMAND_INJECTION_RULE["name"],
        "severity": COMMAND_INJECTION_RULE["severity"],
        "file": file_path,
        "line": line_number,
        "evidence": evidence,
        "description": COMMAND_INJECTION_RULE["description"],
        "recommendation": COMMAND_INJECTION_RULE["recommendation"],
    }
