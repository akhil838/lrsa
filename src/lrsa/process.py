"""Subprocess helpers with consistent command and device-log formatting."""

from __future__ import annotations

import logging
import shlex
import subprocess
from collections.abc import Sequence
from pathlib import Path

DEFAULT_OUTPUT_LIMIT = 12_000


def command_text(command: Sequence[object]) -> str:
    return shlex.join(str(part) for part in command)


def _decode_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def trimmed_output(value: str | bytes | None, limit: int = DEFAULT_OUTPUT_LIMIT) -> str:
    text = _decode_output(value).strip()
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n... <truncated {omitted} chars>"


def format_stream(name: str, value: str | bytes | None) -> str:
    text = trimmed_output(value)
    if not text:
        return f"{name}: <empty>"
    indented = "\n".join(f"  {line}" for line in text.splitlines())
    return f"{name}:\n{indented}"


def format_process_output(
    stdout: str | bytes | None, stderr: str | bytes | None
) -> str:
    return "\n".join(
        [
            format_stream("stdout", stdout),
            format_stream("stderr", stderr),
        ]
    )


def process_error_message(
    label: str,
    command: Sequence[object],
    returncode: int | str,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
) -> str:
    return (
        f"{label} failed with exit code {returncode}: {command_text(command)}\n"
        f"{format_process_output(stdout, stderr)}"
    )


def run_process(
    command: Sequence[object],
    *,
    label: str,
    cwd: str | Path | None = None,
    timeout: int | None = None,
    logger: logging.Logger | None = None,
) -> subprocess.CompletedProcess[str]:
    command_list = [str(part) for part in command]
    if logger:
        logger.info("Running %s: %s", label, command_text(command_list))
    try:
        proc = subprocess.run(
            command_list,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"{label} timed out after {timeout}s: {command_text(command_list)}\n"
            f"{format_process_output(exc.stdout, exc.stderr)}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"{label} could not start: {command_text(command_list)}\n{exc}"
        ) from exc

    if logger and (proc.stdout or proc.stderr):
        logger.debug(
            "%s output\n%s", label, format_process_output(proc.stdout, proc.stderr)
        )
    if proc.returncode != 0:
        raise RuntimeError(
            process_error_message(
                label, command_list, proc.returncode, proc.stdout, proc.stderr
            )
        )
    return proc
