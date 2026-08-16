"""Utility helpers for VW identity login."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger("carconnectivity.connectors.volkswagen.auth")


def check_str(value: object) -> str | None:
    """Return value if it is a non-empty string, otherwise None."""
    return value if isinstance(value, str) and value else None


def safe_int(value: object, default: int) -> int:
    """Convert value to int, returning default on failure."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def dump_html_debug(
    stage: str,
    html: str,
    output_dir: Path,
    url: str | None = None,
) -> Path | None:
    """Write an HTML debug snapshot to output_dir; returns the path or None on failure."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_stage = re.sub(r"[^a-zA-Z0-9_.-]+", "_", stage)
    file_path = output_dir / f"{timestamp}_{safe_stage}.html"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        file_path.write_text(html, encoding="utf-8")
    except OSError as error:
        LOG.warning("Failed to write HTML dump for %s: %s", stage, error)
        return None
    LOG.debug("HTML dump written to %s (url=%s)", file_path, url)
    return file_path
