from pathlib import Path

from .detector import PIIDetector
from .models import DetectedEntity

TEXT_FILE_EXTENSIONS = {
    ".txt", ".py", ".js", ".ts", ".java", ".cs", ".php",
    ".json", ".yaml", ".yml", ".md", ".csv",
}


def scan_file(path: Path, detector: PIIDetector) -> list[DetectedEntity]:
    """Read a text file and return detected entities. Does not modify the file."""
    if path.suffix.lower() not in TEXT_FILE_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {path.suffix}")
    text = path.read_text(encoding="utf-8", errors="replace")
    return detector.detect(text)
