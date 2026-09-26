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
    tainted_function_parameters = {}

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

    # Track simple function definitions and their parameter ranges.
    function_definitions = {}

    for index, line in enumerate(lines):
        function_match = re.search(
            r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)",
            line,
        )

        if not function_match:
            continue

        function_name = function_match.group(1)
        parameters = [
            parameter.strip()
            for parameter in function_match.group(2).split(",")
            if parameter.strip()
        ]

        brace_depth = line.count("{") - line.count("}")
        end_line = index

        while brace_depth > 0 and end_line + 1 < len(lines):
            end_line += 1
            brace_depth += (
                lines[end_line].count("{")
                - lines[end_line].count("}")
            )

        function_definitions[function_name] = {
            "parameters": parameters,
            "start": index,
            "end": end_line,
        }

    # Identify which function parameters receive user-controlled arguments.
    tainted_function_parameters = {}

    for function_name, function_info in function_definitions.items():
        parameters = function_info["parameters"]

        for line in lines:
            call_match = re.search(
                rf"\b{re.escape(function_name)}\s*\(([^)]*)\)",
                line,
            )

            if not call_match:
                continue

            arguments = [
                argument.strip()
                for argument in call_match.group(1).split(",")
            ]

            for index, argument in enumerate(arguments):
                if (
                    index < len(parameters)
                    and re.fullmatch(
                        r"[A-Za-z_$][\w$]*",
                        argument,
                    )
                ):
                    # Check whether the argument is an obvious user-controlled
                    # variable based on its declaration anywhere in the file.
                    for source_line in lines:
                        if re.search(
                            rf"\b(?:const|let|var)\s+"
                            rf"{re.escape(argument)}\s*=\s*"
                            r"(?:request\.(?:query|body|params)\."
                            r"[A-Za-z_$][\w$]*|"
                            r"window\.location(?:\.[A-Za-z_$][\w$]*)?)",
                            source_line,
                        ):
                            tainted_function_parameters.setdefault(
                                function_name,
                                set(),
                            ).add(parameters[index])
                            break

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

                # Track reassignment and update taint state.
        reassignment_match = re.search(
            r"^\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)",
            line,
        )

        if reassignment_match:
            variable_name = reassignment_match.group(1)
            assigned_expression = reassignment_match.group(2)

            # User-controlled source → tainted.
            if re.search(
                r"(?:request\.(?:query|body|params)\.[A-Za-z_$][\w$]*|"
                r"window\.location(?:\.[A-Za-z_$][\w$]*)?)",
                assigned_expression,
            ):
                user_controlled_variables.add(variable_name)

            # Derived from an already-tainted variable → tainted.
            elif any(
                re.search(
                    rf"\b{re.escape(tainted_variable)}\b",
                    assigned_expression,
                )
                for tainted_variable in user_controlled_variables
            ):
                user_controlled_variables.add(variable_name)

            # Otherwise the previous taint is cleared.
            else:
                user_controlled_variables.discard(variable_name)

        # Propagate taint through derived variables.
        derived_variable_match = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)",
            line,
        )

        if derived_variable_match:
            variable_name = derived_variable_match.group(1)
            assigned_expression = derived_variable_match.group(2)

            for tainted_variable in user_controlled_variables:
                if re.search(
                    rf"\b{re.escape(tainted_variable)}\b",
                    assigned_expression,
                ):
                    user_controlled_variables.add(variable_name)
                    break
      
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

                # Include function parameters that are tainted only inside
        # their corresponding function body.
        effective_tainted_variables = set(user_controlled_variables)

        for function_name, function_info in function_definitions.items():
            if (
                function_info["start"]
                < line_number - 1
                <= function_info["end"]
            ):
                effective_tainted_variables.update(
                    tainted_function_parameters.get(
                        function_name,
                        set(),
                    )
                )

                # Include tainted function parameters only inside their
        # corresponding function body.
        effective_tainted_variables = set(user_controlled_variables)

        for function_name, function_info in function_definitions.items():
            if (
                function_info["start"]
                < line_number - 1
                <= function_info["end"]
            ):
                effective_tainted_variables.update(
                    tainted_function_parameters.get(
                        function_name,
                        set(),
                    )
                )

        for pattern, evidence in xss_patterns:
            match = re.search(pattern, line)

            if (
                match
                and match.group(1) in effective_tainted_variables
            ):
                finding = create_xss_finding(
                    file_path=file_path,
                    line_number=line_number,
                    evidence=evidence,
                )

                findings.append(finding)

    return findings
