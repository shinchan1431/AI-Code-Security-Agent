import ast

from backend.scanner.rules import (
    create_sql_injection_finding,
    create_command_injection_finding,
    create_insecure_deserialization_finding,
    create_weak_crypto_finding,
    create_path_traversal_finding,
    create_ssrf_finding,
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

def is_user_controlled_path(node: ast.AST) -> bool:
    """
    Check whether an AST expression appears to originate from
    obvious user-controlled input.
    """

    # Direct input() calls.
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return True

        # request.args.get(...)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr in {"args", "form"}
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "request"
        ):
            return True

    return False

def is_user_controlled_url(node: ast.AST) -> bool:
    """
    Check whether an AST expression appears to originate from
    obvious user-controlled URL input.
    """

    # Direct input() calls.
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return True

        # request.args.get(...)
        # request.form.get(...)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr in {"args", "form"}
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "request"
        ):
            return True

    return False


def analyze_python_file(file_path: str) -> list[dict]:
    """
    Analyze a Python file using the Abstract Syntax Tree (AST).

    Returns:
        A list of security findings.
    """

    findings = []
    user_controlled_variables = set()
    user_controlled_urls = set()

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
        # Track variables assigned from obvious user-controlled input.
        if isinstance(node, ast.Assign):
            if is_user_controlled_path(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        user_controlled_variables.add(target.id)
            if is_user_controlled_url(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                       user_controlled_urls.add(target.id)
        if isinstance(node, ast.Call):

            # Attribute calls such as:
            # cursor.execute(query)
            # os.system(command)
            if isinstance(node.func, ast.Attribute):

                function_name = node.func.attr
                # Detect unsafe pickle deserialization.
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "pickle"
                    and function_name in {"load", "loads"}
                ):
                    finding = create_insecure_deserialization_finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        evidence=(
                            f"pickle.{function_name}() "
                            "deserialization detected."
                        ),
                    )

                    findings.append(finding)
                # Detect weak cryptographic hash algorithms.
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "hashlib"
                    and function_name in {"md5", "sha1"}
                ):
                    finding = create_weak_crypto_finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        evidence=(
                            f"hashlib.{function_name}() "
                            "weak cryptographic hash detected."
                        ),
                    )

                    findings.append(finding)
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

                # Detect file access using user-controlled paths.
                if function_name == "open":
                    if node.args and isinstance(node.args[0], ast.Name):
                        if node.args[0].id in user_controlled_variables:
                            finding = create_path_traversal_finding(
                                file_path=file_path,
                                line_number=node.lineno,
                                evidence=(
                                    "open() called with a path derived "
                                    "from user-controlled input."
                                ),
                            )

                            findings.append(finding)

                # Detect network requests using user-controlled URLs.
                if function_name == "urlopen":
                    if node.args and isinstance(node.args[0], ast.Name):
                        if node.args[0].id in user_controlled_urls:
                            finding = create_ssrf_finding(
                                file_path=file_path,
                                line_number=node.lineno,
                                evidence=(
                                    "urlopen() called with a URL derived "
                                    "from user-controlled input."
                                ),
                            )

                            findings.append(finding)

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
