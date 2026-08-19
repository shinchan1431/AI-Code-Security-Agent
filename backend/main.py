from scanner.repository import clone_repository
from scanner.file_scanner import find_source_files


def main():
    print("🔐 AI Code Security Agent")
    print("--------------------------")

    repository_url = input("Enter GitHub repository URL: ")

    try:
        repository_path = clone_repository(repository_url)

        print("\n✅ Repository cloned successfully!")
        print(f"📁 Location: {repository_path}")

        source_files = find_source_files(repository_path)

        print(f"\n🔎 Source files found: {len(source_files)}")

        for file_path in source_files:
            print(f"  • {file_path}")

    except ValueError as error:
        print(f"\n❌ Invalid repository: {error}")

    except Exception as error:
        print(f"\n❌ Failed to scan repository: {error}")


if __name__ == "__main__":
    main()
