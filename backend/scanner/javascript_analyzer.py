import re
class TaintState:
    """Track variables and properties that carry user-controlled data."""

    def __init__(self):
        self.variables = set()
        self.object_properties = set()

    def add(self, variable_name: str) -> None:
        self.variables.add(variable_name)

    def remove(self, variable_name: str) -> None:
        self.variables.discard(variable_name)

    def contains(self, variable_name: str) -> bool:
        return variable_name in self.variables

    def is_tainted(self, variable_name: str) -> bool:
        """Return whether a variable currently carries tainted data."""
        return variable_name in self.variables

    def propagate_from_expression(
        self,
        variable_name: str,
        expression: str,
        additional_tainted_variables=None,
    ) -> bool:
        """Propagate taint when an expression references a tainted variable."""
        tainted_variables = set(self.variables)

        if additional_tainted_variables:
            tainted_variables.update(additional_tainted_variables)


        for tainted_variable in tainted_variables:
            if re.search(
                rf"\b{re.escape(tainted_variable)}\b",
                expression,
            ):
                self.add(variable_name)
                return True

        return False

    def add_property(self, property_name: str) -> None:
        self.object_properties.add(property_name)

    def contains_property(self, property_name: str) -> bool:
        return property_name in self.object_properties
    def propagate_function_return(
        self,
        variable_name: str,
        function_name: str,
        arguments: list[str],
        function_definitions: dict,
    ) -> bool:
        """Propagate taint through a function that returns a parameter."""
        function_info = function_definitions.get(function_name)

        if not function_info:
            return False

        returned_parameter = function_info.get("returns_parameter")

        if not returned_parameter:
            return False

        try:
            parameter_index = function_info["parameters"].index(
                returned_parameter
            )
        except ValueError:
            return False

        if parameter_index >= len(arguments):
            return False

        argument = arguments[parameter_index].strip()

        if self.is_tainted(argument):
            self.add(variable_name)
            return True

        return False

from backend.scanner.rules import (
    create_command_injection_finding,
    create_sql_injection_finding,
    create_xss_finding,
    create_prototype_pollution_finding,
    create_js_path_traversal_finding,
    create_js_ssrf_finding,
)


def analyze_javascript_file(file_path: str) -> list[dict]:
    """
    Analyze a JavaScript or TypeScript file for dangerous patterns.

    Returns:
        A list of security findings.
    """

    findings = []
    taint_state = TaintState()

    user_controlled_variables = taint_state.variables
    tainted_object_properties = taint_state.object_properties

    tainted_function_parameters = {}
    prototype_pollution_keys = set()
    path_traversal_variables = set()
    ssrf_variables = set()

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
        returns_parameter = None

        for function_line in lines[index : end_line + 1]:
            return_match = re.search(
                r"\breturn\s+([A-Za-z_$][\w$]*)\s*;?",
                function_line,
            )

            if return_match and return_match.group(1) in parameters:
                returns_parameter = return_match.group(1)
                break

        function_definitions[function_name] = {
            "parameters": parameters,
            "start": index,
            "end": end_line,
            "returns_parameter": returns_parameter,
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
                    # Check whether the argument is already tainted.
                    # This allows SSRF and other data-flow taint to cross
                    # function boundaries.
                    argument_is_tainted = taint_state.is_tainted(argument)

                    # Also check whether the argument is directly assigned
                    # from an obvious user-controlled source.
                    if not argument_is_tainted:
                        for source_line in lines:
                            if re.search(
                                rf"\b(?:const|let|var)\s+"
                                rf"{re.escape(argument)}\s*=\s*"
                                r"(?:request\.(?:query|body|params)\."
                                r"[A-Za-z_$][\w$]*|"
                                r"window\.location(?:\.[A-Za-z_$][\w$]*)?)",
                                source_line,
                            ):
                                argument_is_tainted = True
                                break

                    if argument_is_tainted:
                        tainted_function_parameters.setdefault(
                            function_name,
                            set(),
                        ).add(parameters[index])
    for line_number, line in enumerate(lines, start=1):
        effective_tainted_variables = set(user_controlled_variables)
        # Track user-controlled property keys.
        property_key_match = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:request\.(?:query|body|params)|req\.(?:query|body|params))"
            r"\.[A-Za-z_$][\w$]*",
            line,
        )

        if property_key_match:
            prototype_pollution_keys.add(property_key_match.group(1))

        # Track user-controlled values used for filesystem paths.
        path_input_match = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:request\.(?:query|body|params)|req\.(?:query|body|params))"
            r"\.[A-Za-z_$][\w$]*",
            line,
        )

        if path_input_match:
            path_traversal_variables.add(path_input_match.group(1))

        # Detect filesystem operations using user-controlled path values.
        path_traversal_match = re.search(
            r"\b(?:fs|fsp|fileSystem)\."
            r"(?:readFile|readFileSync|writeFile|writeFileSync|"
            r"appendFile|appendFileSync|open|openSync|unlink|unlinkSync|"
            r"mkdir|mkdirSync|readdir|readdirSync)\s*"
            r"\([^)]*\b([A-Za-z_$][\w$]*)\b[^)]*\)",
            line,
        )

        if (
            path_traversal_match
            and path_traversal_match.group(1)
            in path_traversal_variables
        ):
            findings.append(
                create_js_path_traversal_finding(
                    file_path,
                    line_number,
                    line.strip(),
                )
            )
        # Track user-controlled values used as request destinations.
        ssrf_input_match = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:request\.(?:query|body|params)|req\.(?:query|body|params))"
            r"\.[A-Za-z_$][\w$]*",
            line,
        )

        if ssrf_input_match:
            ssrf_variables.add(ssrf_input_match.group(1))

        # Track URL objects created from SSRF-tainted values.
        # Example:
        # const target = request.query.url;
        # const url = new URL(target);
        url_constructor_match = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"new\s+URL\s*\(\s*([A-Za-z_$][\w$]*)\s*",
            line,
        )

        if (
            url_constructor_match
            and url_constructor_match.group(2) in ssrf_variables
        ):
            ssrf_variables.add(url_constructor_match.group(1))

        # Detect server-side HTTP requests using user-controlled destinations.
        ssrf_match = re.search(
            r"\b(?:fetch|axios\.(?:get|post|put|delete|request)|"
            r"http\.(?:get|request)|https\.(?:get|request))\s*"
            r"\([^)]*\b([A-Za-z_$][\w$]*)\b[^)]*\)",
            line,
        )

        # Include SSRF-tainted function parameters while analyzing
        # their corresponding function body.
        effective_ssrf_variables = set(ssrf_variables)

        for function_name, function_info in function_definitions.items():
            if (
                function_info["start"]
                < line_number - 1
                <= function_info["end"]
            ):
                effective_ssrf_variables.update(
                    tainted_function_parameters.get(
                        function_name,
                        set(),
                    )
                )

        if (
            ssrf_match
            and ssrf_match.group(1) in effective_ssrf_variables
        ):
            findings.append(
                create_js_ssrf_finding(
                    file_path,
                    line_number,
                    line.strip(),
                )
            )
        # Detect explicit dangerous prototype property writes.
        dangerous_prototype_match = re.search(
            r"\b[A-Za-z_$][\w$]*\s*\[\s*['\"]__proto__['\"]\s*\]\s*=",
            line,
        )

        if dangerous_prototype_match:
            findings.append(
                create_prototype_pollution_finding(
                    file_path,
                    line_number,
                    line.strip(),
                )
            )
        # Detect constructor.prototype pollution.
        constructor_prototype_match = re.search(
            r"\b[A-Za-z_$][\w$]*\s*\[\s*['\"]constructor['\"]\s*\]"
            r"\s*\[\s*['\"]prototype['\"]\s*\]\s*=",
            line,
        )
        if constructor_prototype_match:
            findings.append(
                create_prototype_pollution_finding(
                    file_path,
                    line_number,
                    line.strip(),
                )
            )
        # Detect dynamic property writes using user-controlled keys.
        dynamic_property_match = re.search(
            r"\b([A-Za-z_$][\w$]*)\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*=",
            line,
        )

        if (
            dynamic_property_match
            and dynamic_property_match.group(2)
            in prototype_pollution_keys
        ):
            findings.append(
                create_prototype_pollution_finding(
                    file_path,
                    line_number,
                    line.strip(),
                )
            )
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
            elif taint_state.propagate_from_expression(
                variable_name,
                assigned_expression,
                effective_tainted_variables,
            ):
                pass
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

            effective_tainted_variables = set(user_controlled_variables)
            # Propagate SSRF taint through derived variables.
            if any(
                re.search(
                    rf"\b{re.escape(ssrf_variable)}\b",
                    assigned_expression,
                )
                for ssrf_variable in ssrf_variables
            ):
                ssrf_variables.add(variable_name)
            # Include tainted function parameters inside their function body.
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
            # Handle a direct function call separately so that a tainted
            # argument does not automatically taint the return value.
            function_call_match = re.fullmatch(
                r"\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*;?",
                assigned_expression,
            )

            if function_call_match:
                called_function = function_call_match.group(1)
                arguments = [
                    argument.strip()
                    for argument in function_call_match.group(2).split(",")
                    if argument.strip()
                ]

                function_info = function_definitions.get(called_function)

                if function_info:
                    taint_state.propagate_function_return(
                        variable_name,
                        called_function,
                        arguments,
                        function_definitions,
                    )

            else:
                # Non-function expressions can inherit taint from
                # already-tainted variables.
                taint_state.propagate_from_expression(
                    variable_name,
                    assigned_expression,
                    effective_tainted_variables,
                )
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
        # Track simple object properties that receive tainted values.
        object_property_match = re.search(
            r"^\s*([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*,?\s*$",
            line,
        )

        if object_property_match:
            property_name = object_property_match.group(1)
            property_value = object_property_match.group(2)

            if property_value in effective_tainted_variables:
                # Find the nearest object declaration above this property.
                for previous_index in range(line_number - 2, -1, -1):
                    previous_line = lines[previous_index]

                    object_match = re.search(
                        r"\b(?:const|let|var)\s+"
                        r"([A-Za-z_$][\w$]*)\s*=\s*\{",
                        previous_line,
                    )

                    if object_match:
                        object_name = object_match.group(1)
                        tainted_object_properties.add(
                            f"{object_name}.{property_name}"
                        )
                        break
        # Detect dangerous JavaScript HTML/document sinks
        # when their input is user-controlled.
        xss_patterns = [
            (
                r"\.innerHTML\s*=\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*;?",
                "JavaScript innerHTML assignment detected.",
            ),
            (
                r"\.outerHTML\s*=\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*;?",
                "JavaScript outerHTML assignment detected.",
            ),
            (
               r"\.insertAdjacentHTML\s*\(\s*[^,]+,\s*"
               r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\)",
               "JavaScript insertAdjacentHTML() call detected.",
            ),
            (
                r"\bdocument\.write\s*\(\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\)",
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

        for pattern, evidence in xss_patterns:
            match = re.search(pattern, line)

            if (
                match
                and (
                    match.group(1) in effective_tainted_variables
                    or match.group(1) in tainted_object_properties
                )
            ):
                finding = create_xss_finding(
                    file_path=file_path,
                    line_number=line_number,
                    evidence=evidence,
                )

                findings.append(finding)

    return findings
