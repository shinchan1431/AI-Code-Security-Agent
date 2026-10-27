from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_xss_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 4

    assert findings[0]["type"] == "xss"
    assert findings[0]["line"] == 3
    assert "innerHTML" in findings[0]["evidence"]

    assert findings[1]["type"] == "xss"
    assert findings[1]["line"] == 5
    assert "outerHTML" in findings[1]["evidence"]

    assert findings[2]["type"] == "xss"
    assert findings[2]["line"] == 7
    assert "insertAdjacentHTML" in findings[2]["evidence"]

    assert findings[3]["type"] == "xss"
    assert findings[3]["line"] == 9
    assert "document.write" in findings[3]["evidence"]


def test_safe_javascript_html_sinks_are_ignored():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_xss_derived_variable_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_derived.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 4
    assert "innerHTML" in findings[0]["evidence"]
def test_javascript_xss_two_hop_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_two_hop.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 5
    assert "innerHTML" in findings[0]["evidence"]
def test_javascript_xss_reassignment_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_reassignment.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 5
    assert "innerHTML" in findings[0]["evidence"]
def test_safe_xss_reassignment_is_ignored():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_reassignment_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []

def test_javascript_xss_function_parameter_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_function_parameter.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 6
    assert "innerHTML" in findings[0]["evidence"]

def test_javascript_xss_function_parameter_derived_variable_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_parameter_derived.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 7
    assert "innerHTML" in findings[0]["evidence"]
def test_javascript_xss_function_return_safe_value():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_function_return_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 0
def test_javascript_xss_function_return_transform_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_return_transform.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["type"] == "xss"
    assert xss_findings[0]["severity"] == "HIGH"
    assert xss_findings[0]["line"] == 9


def test_javascript_xss_function_return_transform_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_function_return_transform_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []

def test_javascript_xss_object_property():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_object_property.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 7
def test_javascript_xss_object_property_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_object_property_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
def test_javascript_xss_function_return_object_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_return_object.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["type"] == "xss"
    assert xss_findings[0]["severity"] == "HIGH"
    assert xss_findings[0]["line"] == 11


def test_javascript_xss_function_return_object_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_function_return_object_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
def test_javascript_xss_object_property_function_argument_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_property_function_arg.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["type"] == "xss"
    assert xss_findings[0]["severity"] == "HIGH"
    assert xss_findings[0]["line"] == 8


def test_javascript_xss_object_property_function_argument_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_object_property_function_arg_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []


def test_javascript_xss_object_alias_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_alias.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["type"] == "xss"
    assert xss_findings[0]["severity"] == "HIGH"
    assert xss_findings[0]["line"] == 9


def test_javascript_xss_object_alias_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_object_alias_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []


def test_javascript_xss_object_alias_reassignment_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_object_alias_reassignment_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []


def test_javascript_xss_object_alias_reassignment_clears_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_alias_reassignment.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []


def test_javascript_xss_tracks_only_tainted_object_property():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_multiple_properties.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 8


def test_javascript_xss_does_not_cross_taint_between_objects():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_separate_objects.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 12


def test_javascript_xss_safe_object_property_reassignment():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_property_reassignment_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []

def test_javascript_xss_detects_tainted_object_property_reassignment():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_property_reassignment_tainted.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 9

def test_javascript_xss_object_mutated_by_function():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_mutated_by_function.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["type"] == "xss"
    assert xss_findings[0]["severity"] == "HIGH"
    assert xss_findings[0]["line"] == 10


def test_javascript_xss_object_mutated_by_function_safe_input():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_mutated_by_function_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []


def test_javascript_xss_object_mutated_by_function_safe_overwrite():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_mutated_by_function_safe_overwrite.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []

def test_javascript_xss_detected_before_safe_function_overwrite():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_mutation_sink_before_safe_overwrite.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 10

def test_javascript_xss_same_line_safe_function_overwrite():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_same_line_safe_overwrite.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []


def test_javascript_xss_function_multiple_calls_keep_object_taint_separate():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_multiple_calls.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 7


def test_javascript_xss_function_taint_then_safe_overwrite():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_taint_then_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 8


def test_javascript_xss_function_safe_then_tainted_overwrite():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_safe_then_taint.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 11


def test_javascript_xss_detects_tainted_cross_object_property_copy():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_cross_object_property_copy.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 14


def test_javascript_xss_conditional_safe_overwrite_preserves_possible_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_conditional_safe_overwrite.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 8

def test_javascript_xss_if_else_both_safe_overwrites_clear_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_if_else_both_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []


def test_javascript_xss_nested_if_else_preserves_possible_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_nested_if_else_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1


def test_javascript_xss_unconditional_safe_overwrite_clears_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_conditional_then_unconditional_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []


def test_javascript_xss_object_alias_tainted_after_alias_creation():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_alias_taint_after_alias.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 5


def test_javascript_xss_alias_reassignment_preserves_original_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_alias_reassignment_preserves_original.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 11


def test_javascript_xss_shared_alias_safe_property_overwrite_clears_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_shared_alias_safe_property_overwrite.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []


def test_javascript_xss_shared_alias_tainted_overwrite_propagates_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_shared_alias_tainted_overwrite.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 12


def test_javascript_xss_multiple_alias_reassignment_preserves_remaining_aliases():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_multiple_alias_reassignment.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 2
    assert [finding["line"] for finding in xss_findings] == [14, 15]


def test_javascript_xss_tainted_property_copy_through_alias():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_tainted_property_copy_through_alias.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 15


def test_javascript_xss_chained_property_copy_propagates_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_chained_property_copy.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 18

def test_javascript_xss_nested_object_property():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_nested_object_property.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 7


def test_javascript_xss_nested_property_safe_overwrite_clears_taint():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_nested_safe_overwrite.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert xss_findings == []

def test_javascript_xss_nested_object_property_with_brace_in_string():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_nested_brace_string.js"
    )
    findings = analyze_javascript_file(str(fixture))
    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]
    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 8

def test_javascript_xss_nested_object_property_with_multiline_comment():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_multiline_comment.js"
    )
    findings = analyze_javascript_file(str(fixture))
    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]
    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 10


def test_javascript_xss_array_index_taint_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_array_index.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["line"] == 3
    assert "innerHTML" in findings[0]["evidence"]


def test_javascript_xss_safe_array_index_is_ignored():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_array_index_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []


def test_javascript_xss_array_index_with_comma_in_string():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_array_index_comma.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["line"] == 3


def test_javascript_xss_dynamic_array_index_taint_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_array_dynamic_index.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 4
    assert "innerHTML" in xss_findings[0]["evidence"]


def test_javascript_xss_safe_dynamic_array_index_is_ignored():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_array_dynamic_index_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []


def test_javascript_xss_object_destructuring_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_destructuring.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 6


def test_javascript_xss_object_destructuring_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_object_destructuring_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []


def test_javascript_xss_object_destructuring_renamed_property():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_destructuring_renamed.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["line"] == 6


def test_javascript_xss_object_destructuring_multiple_properties():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_destructuring_multiple.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 2
    assert [finding["line"] for finding in xss_findings] == [8, 9]


def test_javascript_xss_object_destructuring_mixed_safe_property():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_object_destructuring_mixed_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
