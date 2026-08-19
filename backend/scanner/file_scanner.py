import os


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".cs",
    ".go",
    ".php",
    ".rb",
}


def find_source_files(repository_path: str) -> list[str]:
    """
    Find source-code files inside a cloned repository.

    Args:
        repository_path: Path to the cloned repository.

    Returns:
        A list of source-code file paths.
    """

    source_files = []

    for root, directories, files in os.walk(repository_path):

        # Ignore directories that aren't useful for source analysis.
        directories[:] = [
            directory
            for directory in directories
            if directory not in {
                ".git",
                ".venv",
                "venv",
                "node_modules",
                "__pycache__",
            }
        ]

        for filename in files:
            extension = os.path.splitext(filename)[1].lower()

            if extension in SUPPORTED_EXTENSIONS:
                source_files.append(os.path.join(root, filename))

    return source_files
