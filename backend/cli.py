import argparse

from backend.reporting.json_reporter import write_json_report
from backend.scanner.scan_engine import scan_repository


def main():
    parser = argparse.ArgumentParser(
        prog="ai-code-security-agent",
        description="AI Code Security Agent - Static Security Scanner",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local repository or GitHub repository",
    )

    scan_parser.add_argument(
        "repository",
        help="Path to the repository to scan",
    )

    scan_parser.add_argument(
        "--output",
        default="reports/scan_report.json",
        help="Path for the JSON report",
    )

    args = parser.parse_args()

    if args.command == "scan":
        result = scan_repository(args.repository)

        print("\n=== AI Code Security Agent ===")
        print(f"Status: {result.status}")

        if result.status == "failed":
            print(f"Error: {result.error}")
            raise SystemExit(1)

        print(f"Repository: {result.repository}")
        print(f"Files found: {result.summary.files_found}")
        print(f"Files scanned: {result.summary.files_scanned}")
        print(f"Findings: {result.summary.findings}")

        print("\nSeverity:")
        print(f"  Critical: {result.summary.critical}")
        print(f"  High:     {result.summary.high}")
        print(f"  Medium:   {result.summary.medium}")
        print(f"  Low:      {result.summary.low}")

        report_path = write_json_report(
            result,
            args.output,
        )

        print(f"\nJSON report: {report_path}")

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


if __name__ == "__main__":
    main()
