import os
import shutil
import stat
import tempfile
from urllib.parse import urlparse

from git import Repo


def remove_readonly(func, path, exc_info):
    """
    Handle read-only files during Windows cleanup.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)

def is_github_repository_url(repo_url: str) -> bool:
    """
    Check whether a URL is a valid HTTPS GitHub repository URL.
    """
    parsed_url = urlparse(repo_url)

    if parsed_url.scheme != "https":
        return False

    if parsed_url.netloc.lower() != "github.com":
        return False

    path_parts = parsed_url.path.strip("/").split("/")

    return len(path_parts) == 2 and all(path_parts)


def cleanup_repository(repository_path: str):
    """
    Remove a temporary cloned repository safely.
    """
    if not repository_path:
        return

    shutil.rmtree(
        repository_path,
        onerror=remove_readonly,
    )


def clone_repository(repo_url: str) -> str:
    """
    Clone a GitHub repository into a temporary directory.

    Returns:
        str: Path to the cloned repository.
    """

    if not is_github_repository_url(repo_url):
        raise ValueError("Only HTTPS GitHub repositories are supported.")

    temp_directory = tempfile.mkdtemp(prefix="security_scan_")

    try:
        repo = Repo.clone_from(repo_url, temp_directory)
        repo.close()
        return temp_directory

    except Exception:
        cleanup_repository(temp_directory)
        raise