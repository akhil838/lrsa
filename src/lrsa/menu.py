"""Compatibility shim for the removed terminal menu.

The interactive terminal menu has been replaced by the PySide6 desktop GUI.
"""

from __future__ import annotations

from .gui import main

__all__ = ["main"]
