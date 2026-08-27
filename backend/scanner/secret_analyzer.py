import re
from pathlib import Path

from backend.scanner.rules import create_hardcoded_secret_finding


SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    },
    {
        "name": "Generic API Key",
        "pattern": re.compile(
            r"(?i)\b(api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]{16,}['\"]"
        ),
    },
    {
        "name": "Generic Secret",
        "pattern": re.compile(
            r"(?i)\b(secret|password|passwd|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    },
]


def analyze_secrets(file_path: str) -> list[dict]:
    """
    Scan a source file for potential hardcoded secrets.

    Returns:
        A list of security findings.
    """

    findings = []

    try:
        source_code = Path(file_path).read_text(encoding="utf-8")
    except OSError as error:
        return [
            {
                "type": "analysis_error",
                "file": file_path,
                "message": str(error),
            }
        ]

    for line_number, line in enumerate(
        source_code.splitlines(),
        start=1,
    ):
        for secret_pattern in SECRET_PATTERNS:
            if secret_pattern["pattern"].search(line):
                finding = create_hardcoded_secret_finding(
                    file_path=file_path,
                    line_number=line_number,
                    evidence=(
                        f"{secret_pattern['name']} pattern detected."
                    ),
                )

                findings.append(finding)
                break

    return findings