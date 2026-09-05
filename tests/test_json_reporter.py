import json
from pathlib import Path

from backend.reporting.json_reporter import write_json_report
from backend.scanner.scan_engine import scan_repository

TESTS_DIR = Path(__file__).resolve().parent


def test_json_report_is_created(tmp_path):
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    output_path = tmp_path / "scan_report.json"

    report_path = write_json_report(
        result,
        str(output_path),
    )

    assert Path(report_path).exists()


def test_json_report_contains_scan_data(tmp_path):
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    output_path = tmp_path / "scan_report.json"

    write_json_report(
        result,
        str(output_path),
    )

    with open(output_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["status"] == "completed"
    assert "repository" in report
    assert "scan_started_at" in report
    assert "scan_completed_at" in report
    assert "summary" in report
    assert "findings" in report
    assert "analysis_errors" in report


def test_json_report_contains_findings(tmp_path):
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    output_path = tmp_path / "scan_report.json"

    write_json_report(
        result,
        str(output_path),
    )

    with open(output_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    rule_ids = {
        finding["rule_id"]
        for finding in report["findings"]
    }

    assert "PY-CMD-001" in rule_ids
    assert "PY-SQL-001" in rule_ids


def test_json_report_summary_matches_result(tmp_path):
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    output_path = tmp_path / "scan_report.json"

    write_json_report(
        result,
        str(output_path),
    )

    with open(output_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["summary"]["files_scanned"] == result.summary.files_scanned
    assert report["summary"]["findings"] == result.summary.findings
    assert report["summary"]["critical"] == result.summary.critical
    assert report["summary"]["high"] == result.summary.high
    assert report["summary"]["medium"] == result.summary.medium
    assert report["summary"]["low"] == result.summary.low
