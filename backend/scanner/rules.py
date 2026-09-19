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
HARDCODED_SECRET_RULE = {
    "id": "PY-SEC-001",
    "name": "Potential Hardcoded Secret",
    "severity": "HIGH",
    "description": (
        "A potential secret appears to be hardcoded directly "
        "in source code."
    ),
    "recommendation": (
        "Move secrets to environment variables or a secure "
        "secrets manager and rotate exposed credentials."
    ),
}


def create_hardcoded_secret_finding(
    file_path: str,
    line_number: int,
    evidence: str,
) -> dict:
    """
    Create a standardized hardcoded secret security finding.
    """
    return {
        "rule_id": HARDCODED_SECRET_RULE["id"],
        "type": "hardcoded_secret",
        "name": HARDCODED_SECRET_RULE["name"],
        "severity": HARDCODED_SECRET_RULE["severity"],
        "file": file_path,
        "line": line_number,
        "evidence": evidence,
        "description": HARDCODED_SECRET_RULE["description"],
        "recommendation": HARDCODED_SECRET_RULE["recommendation"],
    }
XSS_RULE = {
    "id": "JS-XSS-001",
    "name": "Potential Cross-Site Scripting (XSS)",
    "severity": "HIGH",
    "description": (
        "Untrusted input may be written directly into an HTML "
        "or document sink, potentially allowing script injection."
    ),
    "recommendation": (
        "Avoid inserting untrusted input into HTML sinks. "
        "Prefer safe DOM APIs such as textContent and validate "
        "or sanitize untrusted data before rendering."
    ),
}


def create_xss_finding(
    file_path: str,
    line_number: int,
    evidence: str,
) -> dict:
    """
    Create a standardized XSS security finding.
    """
    return {
        "rule_id": XSS_RULE["id"],
        "type": "xss",
        "name": XSS_RULE["name"],
        "severity": XSS_RULE["severity"],
        "file": file_path,
        "line": line_number,
        "evidence": evidence,
        "description": XSS_RULE["description"],
        "recommendation": XSS_RULE["recommendation"],
    }
INSECURE_DESERIALIZATION_RULE = {
    "id": "PY-SEC-002",
    "name": "Potential Insecure Deserialization",
    "severity": "HIGH",
    "description": (
        "Untrusted or potentially unsafe serialized data may be "
        "deserialized in a way that can lead to code execution."
    ),
    "recommendation": (
        "Avoid deserializing untrusted data with unsafe mechanisms "
        "such as pickle. Use safer serialization formats such as JSON "
        "when possible, or strictly validate and control the source "
        "of serialized data."
    ),
}


def create_insecure_deserialization_finding(
    file_path: str,
    line_number: int,
    evidence: str,
) -> dict:
    """
    Create a standardized insecure deserialization security finding.
    """
    return {
        "rule_id": INSECURE_DESERIALIZATION_RULE["id"],
        "type": "insecure_deserialization",
        "name": INSECURE_DESERIALIZATION_RULE["name"],
        "severity": INSECURE_DESERIALIZATION_RULE["severity"],
        "file": file_path,
        "line": line_number,
        "evidence": evidence,
        "description": INSECURE_DESERIALIZATION_RULE["description"],
        "recommendation": INSECURE_DESERIALIZATION_RULE["recommendation"],
    }
