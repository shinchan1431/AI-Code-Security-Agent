import json
from pathlib import Path

from backend.scanner.scan_models import ScanResult


def write_json_report(
    result: ScanResult,
    output_path: str = "scan_report.json",
) -> str:
    """
    Write a ScanResult to a JSON report file.

    Args:
        result: Structured result returned by the scan engine.
        output_path: Destination path for the JSON report.

    Returns:
        The path to the generated report.
    """

    output_file = Path(output_path)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(
            result.to_dict(),
            file,
            indent=4,
        )

    return str(output_file)


if __name__ == "__main__":
    print(
        "json_reporter.py provides the "
        "write_json_report() function."
    )