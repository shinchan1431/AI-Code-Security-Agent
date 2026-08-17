import os
import shutil
import tempfile
from urllib.parse import urlparse

from git import Repo


def clone_repository(repo_url: str) -> str:
    """
    Clone a GitHub repository into a temporary directory.

    Returns:
        str: Path to the cloned repository.
    """

    parsed_url = urlparse(repo_url)

    if parsed_url.netloc.lower() != "github.com":
        raise ValueError("Only GitHub repositories are supported.")

    temp_directory = tempfile.mkdtemp(prefix="security_scan_")

    try:
        Repo.clone_from(repo_url, temp_directory)
        return temp_directory

    except Exception:
        shutil.rmtree(temp_directory, ignore_errors=True)
        raise
