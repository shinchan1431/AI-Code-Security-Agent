import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from backend.reporting.json_reporter import write_json_report
from backend.scanner.repository import (
    clone_repository,
    cleanup_repository,
    is_github_repository_url,
)
from backend.scanner.secret_analyzer import analyze_secrets
from backend.scanner.ast_analyzer import analyze_python_file
from backend.scanner.file_scanner import find_source_files
from backend.scanner.scan_models import ScanResult, ScanSummary


def normalize_finding_path(finding: dict, repository: Path) -> dict:
    """
    Convert an absolute finding path into a repository-relative path.
    """
    file_path = finding.get("file")

    if file_path:
        try:
            finding["file"] = Path(file_path).relative_to(repository).as_posix()
        except ValueError:
            # If the path is not relative to repository, leave it unchanged
            pass

    return finding


def scan_repository(repository_path: str) -> ScanResult:
    """
    Run the security scanner against a repository.
    """

    start_time = datetime.now(timezone.utc)
    temporary_repository = None
    display_repository = repository_path

    if is_github_repository_url(repository_path):
        try:
            temporary_repository = clone_repository(repository_path)
            repository = Path(temporary_repository)
        except Exception as exc:
            return ScanResult(
                status="failed",
                repository=repository_path,
                scan_started_at=start_time.isoformat(),
                scan_completed_at=datetime.now(timezone.utc).isoformat(),
                error=f"Failed to clone GitHub repository: {exc}",
            )
    else:
        repository = Path(repository_path)

    try:
        if not repository.exists():
            return ScanResult(
                status="failed",
                repository=display_repository,
                scan_started_at=start_time.isoformat(),
                scan_completed_at=datetime.now(timezone.utc).isoformat(),
                error=f"Repository path does not exist: {repository_path}",
            )

        if not repository.is_dir():
            return ScanResult(
                status="failed",
                repository=display_repository,
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
                    finding = normalize_finding_path(finding, repository)
                    if finding.get("type") == "analysis_error":
                        analysis_errors.append(finding)
                    else:
                        findings.append(finding)

                secret_findings = analyze_secrets(file_path)
                for finding in secret_findings:
                    finding = normalize_finding_path(finding, repository)
                    if finding.get("type") == "analysis_error":
                        analysis_errors.append(finding)
                    else:
                        findings.append(finding)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
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
            repository=display_repository,
            scan_started_at=start_time.isoformat(),
            scan_completed_at=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            findings=findings,
            analysis_errors=analysis_errors,
        )

    finally:
        if temporary_repository:
            try:
                cleanup_repository(temporary_repository)
            except Exception as cleanup_error:
                print(
                    f"Warning: failed to remove temporary repository "
                    f"{temporary_repository}: {cleanup_error}"
                )


# ------------------ TEST ------------------

def test_finding_paths_are_repository_relative(tmp_path):
    """
    Ensure that findings returned by scan_repository
    have repository-relative paths, not absolute ones.
    """
    # Create a fake repository path for testing
    repository_path = tmp_path / "vulnerable"
    repository_path.mkdir()

    # Run scan
    result = scan_repository(str(repository_path))

    assert result.status == "completed"
    assert result.findings

    for finding in result.findings:
        file_path = finding["file"]
        # Ensure path is not absolute
        assert not Path(file_path).is_absolute()
