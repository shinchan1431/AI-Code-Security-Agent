from scanner.repository import clone_repository


def main():
    print("🔐 AI Code Security Agent")
    print("--------------------------")

    repository_url = input("Enter GitHub repository URL: ")

    try:
        repository_path = clone_repository(repository_url)

        print("\n✅ Repository cloned successfully!")
        print(f"📁 Location: {repository_path}")

    except ValueError as error:
        print(f"\n❌ Invalid repository: {error}")

    except Exception as error:
        print(f"\n❌ Failed to clone repository: {error}")


if __name__ == "__main__":
    main()
