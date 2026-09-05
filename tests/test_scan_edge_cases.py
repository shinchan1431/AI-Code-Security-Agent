from pathlib import Path

from backend.scanner.scan_engine import scan_repository


def test_nonexistent_repository():
    result = scan_repository("this_repository_does_not_exist")

    assert result.status == "failed"
    assert result.error is not None
    assert "does not exist" in result.error


def test_repository_path_is_file(tmp_path):
    file_path = tmp_path / "not_a_repository.txt"
    file_path.write_text("hello", encoding="utf-8")

    result = scan_repository(str(file_path))

    assert result.status == "failed"
    assert result.error is not None
    assert "not a directory" in result.error


def test_empty_repository(tmp_path):
    result = scan_repository(str(tmp_path))

    assert result.status == "completed"
    assert result.summary.files_found == 0
    assert result.summary.files_scanned == 0
    assert result.summary.findings == 0
    assert result.summary.analysis_errors == 0


def test_clean_repository(tmp_path):
    clean_file = tmp_path / "clean.py"
    clean_file.write_text(
        """
message = "Hello world"
number = 42

print(message)
print(number)
""",
        encoding="utf-8",
    )

    result = scan_repository(str(tmp_path))

    assert result.status == "completed"
    assert result.summary.files_found == 1
    assert result.summary.files_scanned == 1
    assert result.summary.findings == 0
    assert result.summary.analysis_errors == 0
    assert result.findings == []


def test_invalid_python_file(tmp_path):
    invalid_file = tmp_path / "invalid.py"
    invalid_file.write_text(
        """
def broken(
this is not valid Python
""",
        encoding="utf-8",
    )

    result = scan_repository(str(tmp_path))

    assert result.status == "completed"
    assert result.summary.files_scanned == 1
    assert result.summary.analysis_errors > 0
