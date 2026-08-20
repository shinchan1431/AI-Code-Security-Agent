from datetime import datetime, timezone
from pathlib import Path

from backend.reporting.json_reporter import write_json_report
from backend.scanner.ast_analyzer import analyze_python_file
from backend.scanner.file_scanner import find_source_files
from backend.scanner.scan_models import ScanResult, ScanSummary


def scan_repository(repository_path: str) -> ScanResult:
    """
    Run the security scanner against a repository.

    Args:
        repository_path: Path to the repository being scanned.

    Returns:
        A structured ScanResult.
    """

    start_time = datetime.now(timezone.utc)

    repository = Path(repository_path)

    if not repository.exists():
        return ScanResult(
            status="failed",
            repository=str(repository),
            scan_started_at=start_time.isoformat(),
            scan_completed_at=datetime.now(timezone.utc).isoformat(),
            error=f"Repository path does not exist: {repository_path}",
        )

    if not repository.is_dir():
        return ScanResult(
            status="failed",
            repository=str(repository),
            scan_started_at=start_time.isoformat(),
            scan_completed_at=datetime.now(timezone.utc).isoformat(),
            error=f"Repository path is not a directory: {repository_path}",
        )

    source_files = find_source_files(str(repository))

    findings = []
    analysis_errors = []

    files_scanned = 0

    for file_path in source_files:
        files_scanned += 1

        extension = Path(file_path).suffix.lower()

        if extension == ".py":
            file_findings = analyze_python_file(file_path)

            for finding in file_findings:
                if finding.get("type") == "analysis_error":
                    analysis_errors.append(finding)
                else:
                    findings.append(finding)

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get("severity")

        if severity in severity_counts:
            severity_counts[severity] += 1

    summary = ScanSummary(
        files_found=len(source_files),
        files_scanned=files_scanned,
        findings=len(findings),
        critical=severity_counts["CRITICAL"],
        high=severity_counts["HIGH"],
        medium=severity_counts["MEDIUM"],
        low=severity_counts["LOW"],
        analysis_errors=len(analysis_errors),
    )

    return ScanResult(
        status="completed",
        repository=str(repository),
        scan_started_at=start_time.isoformat(),
        scan_completed_at=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        findings=findings,
        analysis_errors=analysis_errors,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.scanner.scan_engine "
            "<repository_path>"
        )
        raise SystemExit(1)

    repository_path = sys.argv[1]

    result = scan_repository(repository_path)

    print("\n=== AI Code Security Agent ===")
    print(f"Status: {result.status}")

    if result.status == "failed":
        print(f"Error: {result.error}")
        raise SystemExit(1)

    report_path = write_json_report(result)

    print(f"Repository: {result.repository}")
    print(f"Files found: {result.summary.files_found}")
    print(f"Files scanned: {result.summary.files_scanned}")
    print(f"Findings: {result.summary.findings}")
    print(f"JSON report: {report_path}")

    print("\nSeverity:")
    print(f"  Critical: {result.summary.critical}")
    print(f"  High:     {result.summary.high}")
    print(f"  Medium:   {result.summary.medium}")
    print(f"  Low:      {result.summary.low}")

    if result.analysis_errors:
        print(
            f"\nAnalysis errors: "
            f"{result.summary.analysis_errors}"
        )

    if result.findings:
        print("\nFindings:")

        for finding in result.findings:
            print(
                f"\n[{finding['severity']}] "
                f"{finding['name']}"
            )
            print(f"  Rule: {finding['rule_id']}")
            print(f"  File: {finding['file']}")
            print(f"  Line: {finding['line']}")
            print(f"  Evidence: {finding['evidence']}")