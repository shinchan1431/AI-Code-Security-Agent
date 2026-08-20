from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ScanSummary:
    """Summary statistics for a security scan."""

    files_found: int = 0
    files_scanned: int = 0
    findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    analysis_errors: int = 0


@dataclass
class ScanResult:
    """Complete structured result produced by the scan engine."""

    status: str
    repository: str
    scan_started_at: str
    scan_completed_at: str
    summary: ScanSummary = field(default_factory=ScanSummary)
    findings: list[dict[str, Any]] = field(default_factory=list)
    analysis_errors: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        """Convert the scan result into a JSON-compatible dictionary."""
        return asdict(self)