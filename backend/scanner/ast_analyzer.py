import ast

from backend.scanner.rules import (
    create_sql_injection_finding,
    create_command_injection_finding,
)


def is_shell_true_call(node: ast.Call) -> bool:
    """
    Check whether an AST function call contains shell=True.
    """

    for keyword in node.keywords:
        if keyword.arg == "shell":
            return (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            )

    return False


def analyze_python_file(file_path: str) -> list[dict]:
    """
    Analyze a Python file using the Abstract Syntax Tree (AST).

    Returns:
        A list of security findings.
    """

    findings = []

    try:
        with open(file_path, "r", encoding="utf-8-sig") as file:
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

            # Attribute calls such as:
            # cursor.execute(query)
            # os.system(command)
            if isinstance(node.func, ast.Attribute):

                function_name = node.func.attr

                # Detect subprocess calls using shell=True.
                if (
                    function_name
                    in {
                        "run",
                        "call",
                        "Popen",
                        "check_output",
                    }
                    and is_shell_true_call(node)
                ):
                    finding = create_command_injection_finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        evidence=(
                            f"subprocess {function_name}() "
                            "with shell=True detected."
                        ),
                    )

                    findings.append(finding)

                # Detect database execute() calls.
                if function_name == "execute":
                    finding = create_sql_injection_finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        evidence="Database execute() call detected.",
                    )

                    findings.append(finding)

                # Detect system command execution.
                if function_name in {"system", "popen"}:
                    finding = create_command_injection_finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        evidence=(
                            f"System command function "
                            f"{function_name}() detected."
                        ),
                    )

                    findings.append(finding)

            # Direct calls such as:
            # system(command)
            # popen(command)
            if isinstance(node.func, ast.Name):

                function_name = node.func.id

                if function_name in {"system", "popen"}:
                    finding = create_command_injection_finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        evidence=(
                            f"System command function "
                            f"{function_name}() detected."
                        ),
                    )

                    findings.append(finding)

    return findings