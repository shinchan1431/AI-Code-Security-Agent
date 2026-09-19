import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
VULNERABLE_DIR = PROJECT_ROOT / "tests" / "vulnerable"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "backend.cli", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_help():
    result = run_cli("--help")

    assert result.returncode == 0
    assert "AI Code Security Agent" in result.stdout
    assert "scan" in result.stdout


def test_cli_scan_vulnerable_repository(tmp_path):
    output_file = tmp_path / "scan_report.json"

    result = run_cli(
        "scan",
        str(VULNERABLE_DIR),
        "--output",
        str(output_file),
    )

    assert result.returncode == 0
    assert "Status: completed" in result.stdout
    assert "Files found: 4" in result.stdout
    assert "Files scanned: 4" in result.stdout
    assert "Findings: 8" in result.stdout

    assert output_file.exists()


def test_cli_report_contains_findings(tmp_path):
    output_file = tmp_path / "scan_report.json"

    result = run_cli(
        "scan",
        str(VULNERABLE_DIR),
        "--output",
        str(output_file),
    )

    assert result.returncode == 0

    with open(output_file, "r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["status"] == "completed"
    assert report["summary"]["findings"] == 8


def test_cli_invalid_repository():
    result = run_cli(
        "scan",
        "tests/does_not_exist",
    )

    assert result.returncode == 1
    assert "Status: failed" in result.stdout