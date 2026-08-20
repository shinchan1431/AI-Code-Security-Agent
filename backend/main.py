from scanner.repository import clone_repository
from scanner.file_scanner import find_source_files


def main():
    repository_url = input("Enter GitHub repository URL: ").strip()

    try:
        repository_path = clone_repository(repository_url)

        print(f"\nRepository cloned to: {repository_path}")

        source_files = find_source_files(repository_path)

        print(f"\nSource files found: {len(source_files)}")

        for file_path in source_files:
            print(f"  - {file_path}")

    except ValueError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
