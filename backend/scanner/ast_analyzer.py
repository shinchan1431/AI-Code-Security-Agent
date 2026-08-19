
import ast


def analyze_python_file(file_path: str) -> list[dict]:
    """
    Analyze a Python file using the Abstract Syntax Tree (AST).

    Returns:
        A list of potential security findings.
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
                    findings.append(
                        {
                            "type": "potential_sql_injection",
                            "file": file_path,
                            "line": node.lineno,
                            "message": (
                                "A database execute() call was detected. "
                                "The query should be checked for unsafe "
                                "string construction or untrusted input."
                            ),
                        }
                    )

    return findings
