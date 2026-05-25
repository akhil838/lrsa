"""Shared logging setup for LRSA command-line tools."""

from __future__ import annotations

import logging
import sys

DEFAULT_FORMAT = "%(levelname)s:%(name)s:%(message)s"


def configure_logging(level: int | str = logging.INFO) -> None:
    """Configure console logging once for CLI entrypoints."""
    root = logging.getLogger()
    if root.handlers:
        root.setLevel(level)
        return
    logging.basicConfig(level=level, format=DEFAULT_FORMAT, stream=sys.stdout)


def get_logger(name: str) -> logging.Logger:
    """Return a module logger without configuring global logging."""
    configure_logging()
    return logging.getLogger(name)
