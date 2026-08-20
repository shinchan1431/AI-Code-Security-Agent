from backend.scanner.repository import clone_repository
from backend.scanner.file_scanner import find_source_files
from backend.scanner.ast_analyzer import analyze_python_file


def main():
    repository_url = input("Enter GitHub repository URL: ").strip()

    try:
        repository_path = clone_repository(repository_url)

        print("\nRepository cloned successfully!")
        print(f"Location: {repository_path}")

        source_files = find_source_files(repository_path)

        print(f"\nSource files found: {len(source_files)}")

        total_findings = 0

        for file_path in source_files:
            print(f"\nAnalyzing: {file_path}")

            # Currently AST analyzer supports Python files.
            if file_path.endswith(".py"):
                findings = analyze_python_file(file_path)

                for finding in findings:
                    print(
                        f"  [{finding.get('severity', 'ERROR')}] "
                        f"{finding.get('name', finding.get('type'))}"
                    )

                    print(f"  Line: {finding.get('line', '-')}")

                    print(
                        f"  Evidence: "
                        f"{finding.get('evidence', finding.get('message', ''))}"
                    )

                total_findings += len(findings)

        print(f"\nTotal security findings: {total_findings}")

    except ValueError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
