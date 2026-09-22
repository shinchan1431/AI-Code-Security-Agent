import re

from backend.scanner.rules import (
    create_command_injection_finding,
    create_sql_injection_finding,
    create_xss_finding,
)


def analyze_javascript_file(file_path: str) -> list[dict]:
    """
    Analyze a JavaScript or TypeScript file for dangerous patterns.

    Returns:
        A list of security findings.
    """

    findings = []
    user_controlled_variables = set()

    try:
        with open(file_path, "r", encoding="utf-8-sig") as file:
            source_code = file.read()

    except OSError as error:
        return [
            {
                "type": "analysis_error",
                "file": file_path,
                "message": str(error),
            }
        ]

    lines = source_code.splitlines()

    for line_number, line in enumerate(lines, start=1):

        # Track variables assigned from obvious user-controlled input.
        user_input_match = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:request\.(?:query|body|params)\.[A-Za-z_$][\w$]*|"
            r"window\.location(?:\.[A-Za-z_$][\w$]*)?)",
            line,
        )

        if user_input_match:
            user_controlled_variables.add(user_input_match.group(1))

        # Detect JavaScript eval()
        if re.search(r"\beval\s*\(", line):
            finding = create_command_injection_finding(
                file_path=file_path,
                line_number=line_number,
                evidence="JavaScript eval() call detected.",
            )

            findings.append(finding)

        # Detect Node.js child_process command execution
        if re.search(
            r"\bchild_process\s*\.\s*(exec|execSync)\s*\(",
            line,
        ):
            finding = create_command_injection_finding(
                file_path=file_path,
                line_number=line_number,
                evidence=(
                    "Node.js child_process command execution "
                    "API detected."
                ),
            )

            findings.append(finding)

        # Detect JavaScript database execute() calls
        # that appear to construct SQL using string concatenation.
        if re.search(r"\.\s*execute\s*\(", line):

            surrounding_code = "\n".join(
                lines[line_number - 1 : line_number + 4]
            )

            has_sql = re.search(
                r"(?i)\b(select|insert|update|delete)\b",
                surrounding_code,
            )

            has_concatenation = "+" in surrounding_code

            if has_sql and has_concatenation:
                finding = create_sql_injection_finding(
                    file_path=file_path,
                    line_number=line_number,
                    evidence=(
                        "JavaScript database execute() call "
                        "uses SQL string concatenation."
                    ),
                )

                findings.append(finding)

        # Detect dangerous JavaScript HTML/document sinks
        # when their input is user-controlled.
        xss_patterns = [
            (
                r"\.innerHTML\s*=\s*([A-Za-z_$][\w$]*)\s*;?",
                "JavaScript innerHTML assignment detected.",
            ),
            (
                r"\.outerHTML\s*=\s*([A-Za-z_$][\w$]*)\s*;?",
                "JavaScript outerHTML assignment detected.",
            ),
            (
                r"\.insertAdjacentHTML\s*\(\s*[^,]+,\s*"
                r"([A-Za-z_$][\w$]*)\s*\)",
                "JavaScript insertAdjacentHTML() call detected.",
            ),
            (
                r"\bdocument\.write\s*\(\s*([A-Za-z_$][\w$]*)\s*\)",
                "JavaScript document.write() call detected.",
            ),
        ]

        for pattern, evidence in xss_patterns:
            match = re.search(pattern, line)

            if match and match.group(1) in user_controlled_variables:
                finding = create_xss_finding(
                    file_path=file_path,
                    line_number=line_number,
                    evidence=evidence,
                )

                findings.append(finding)

    return findings
