import ast

from backend.scanner.rules import (
    create_sql_injection_finding,
    create_command_injection_finding,
)


def analyze_python_file(file_path: str) -> list[dict]:
    """
    Analyze a Python file using the Abstract Syntax Tree (AST).
    """

    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            source_code = file.read()

        tree = ast.parse(source_code, filename=file_path)

    except (OSError, SyntaxError) as error:
        return [
            {
                "type": "analysis_error",
                "file": file_path,
                "message": str(error),
            }
        ]

    for node in ast.walk(tree):

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                function_name = node.func.attr

                if function_name == "execute":
                    finding = create_sql_injection_finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        evidence="Database execute() call detected.",
                    )

                    findings.append(finding)

    return findings
