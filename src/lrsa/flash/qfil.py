"""Compatibility exports for LRSA callers using the native qfil package."""

from __future__ import annotations

import shlex
from pathlib import Path

from qfil import (
    discover_firehose_loader,
    discover_qfil_files,
    has_qfil_files,
    resolve_qfil_image_dir,
    select_qfil_set,
)


def quote_arg(arg: object) -> str:
    return shlex.quote(str(arg))


def format_command(command: list[object], cwd: Path) -> str:
    return f"cd {cwd}\n" + " ".join(quote_arg(part) for part in command)


__all__ = [
    "discover_firehose_loader",
    "discover_qfil_files",
    "format_command",
    "has_qfil_files",
    "resolve_qfil_image_dir",
    "select_qfil_set",
]
